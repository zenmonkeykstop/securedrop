# -*- coding: utf-8 -*-

from __future__ import print_function

import logging
import os
import signal
import socket
import time
import traceback
from datetime import datetime
from multiprocessing import Process
from os.path import abspath
from os.path import dirname
from os.path import expanduser
from os.path import join
from os.path import realpath

import mock
import pyotp
import pytest
import requests
import tbselenium.common as cm
from selenium import webdriver
from selenium.common.exceptions import NoAlertPresentException
from selenium.common.exceptions import WebDriverException
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.remote_connection import LOGGER
from selenium.webdriver.support import expected_conditions
from selenium.webdriver.support.ui import WebDriverWait
from sqlalchemy.exc import IntegrityError
from tbselenium.tbdriver import TorBrowserDriver

import journalist_app
import source_app
import tests.utils.env as env
from db import db
from models import Journalist
from sdconfig import config

from tests.functional.journalist_navigation_steps import \
    JournalistNavigationStepsMixin
from tests.functional.source_navigation_steps import \
    SourceNavigationStepsMixin

os.environ["SECUREDROP_ENV"] = "test"

# https://stackoverflow.com/a/34795883/837471
class alert_is_not_present(object):
    """ Expect an alert to not be present."""
    def __call__(self, driver):
        try:
            alert = driver.switch_to.alert
            alert.text
            return False
        except NoAlertPresentException:
            return True

FIREFOX = "firefox"
TORBROWSER = "torbrowser"


class FunctionalTest(object):
    gpg = None
    new_totp = None
    session_expiration = 30
    secret_message = "These documents outline a major government invasion of privacy."
    timeout = 10
    poll_frequency = 0.1

    accept_languages = None
    default_driver_name = TORBROWSER
    driver = None
    firefox_driver = None
    torbrowser_driver = None

    driver_retry_count = 3
    driver_retry_interval = 5

    def _unused_port(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def switch_to_firefox_driver(self):
        if not self.firefox_driver:
            self.create_firefox_driver()
        self.driver = self.firefox_driver
        logging.info("Switched %s to Firefox driver: %s", self, self.driver)

    def switch_to_torbrowser_driver(self):
        if self.torbrowser_driver is None:
            self.create_torbrowser_driver()
        self.driver = self.torbrowser_driver
        logging.info("Switched %s to TorBrowser driver: %s", self, self.driver)

    @pytest.fixture(autouse=True)
    def drivers(self, firefox_webdriver, tbb_webdriver):

        # self.create_firefox_driver()
        self.firefox_driver = firefox_webdriver
        # self.create_torbrowser_driver()
        self.torbrowser_driver = tbb_webdriver
        logging.info("Creating default web driver: %s", self.default_driver_name)
        if self.default_driver_name == FIREFOX:
            self.switch_to_firefox_driver()
        else:
            self.switch_to_torbrowser_driver()
        self.driver.implicitly_wait(0)

        yield

        try:
            if self.torbrowser_driver:
                self.torbrowser_driver.quit()
        except Exception as e:
            logging.error("Error stopping TorBrowser driver: %s", e)

        try:
            if self.firefox_driver:
                self.firefox_driver.quit()
        except Exception as e:
            logging.error("Error stopping Firefox driver: %s", e)

    @pytest.fixture(autouse=True)
    def sd_servers(self):
        logging.info(
            "Starting SecureDrop servers (session expiration = %s)", self.session_expiration
        )

        # Patch the two-factor verification to avoid intermittent errors
        logging.info("Mocking models.Journalist.verify_token")
        with mock.patch("models.Journalist.verify_token", return_value=True):
            logging.info("Mocking source_app.main.get_entropy_estimate")
            with mock.patch("source_app.main.get_entropy_estimate", return_value=8192):

                try:
                    signal.signal(signal.SIGUSR1, lambda _, s: traceback.print_stack(s))

                    source_port = self._unused_port()
                    journalist_port = self._unused_port()

                    self.source_location = "http://127.0.0.1:%d" % source_port
                    self.journalist_location = "http://127.0.0.1:%d" % journalist_port

                    self.source_app = source_app.create_app(config)
                    self.journalist_app = journalist_app.create_app(config)
                    self.journalist_app.config["WTF_CSRF_ENABLED"] = True

                    self.__context = self.journalist_app.app_context()
                    self.__context.push()

                    env.create_directories()
                    db.create_all()
                    self.gpg = env.init_gpg()

                    # Add our test user
                    try:
                        valid_password = "correct horse battery staple profanity oil chewy"
                        user = Journalist(
                            username="journalist", password=valid_password, is_admin=True
                        )
                        user.otp_secret = "JHCOGO7VCER3EJ4L"
                        db.session.add(user)
                        db.session.commit()
                    except IntegrityError:
                        logging.error("Test user already added")
                        db.session.rollback()

                    # This user is required for our tests cases to login
                    self.admin_user = {
                        "name": "journalist",
                        "password": ("correct horse battery staple" " profanity oil chewy"),
                        "secret": "JHCOGO7VCER3EJ4L",
                    }

                    self.admin_user["totp"] = pyotp.TOTP(self.admin_user["secret"])

                    def start_source_server(app):
                        config.SESSION_EXPIRATION_MINUTES = self.session_expiration / 60.0

                        app.run(port=source_port, debug=True, use_reloader=False, threaded=True)

                    def start_journalist_server(app):
                        app.run(port=journalist_port, debug=True, use_reloader=False, threaded=True)

                    self.source_process = Process(
                        target=lambda: start_source_server(self.source_app)
                    )

                    self.journalist_process = Process(
                        target=lambda: start_journalist_server(self.journalist_app)
                    )

                    self.source_process.start()
                    self.journalist_process.start()

                    for tick in range(30):
                        try:
                            requests.get(self.source_location, timeout=1)
                            requests.get(self.journalist_location, timeout=1)
                        except Exception:
                            time.sleep(0.25)
                        else:
                            break
                    yield
                finally:
                    try:
                        self.source_process.terminate()
                    except Exception as e:
                        logging.error("Error stopping source app: %s", e)

                    try:
                        self.journalist_process.terminate()
                    except Exception as e:
                        logging.error("Error stopping source app: %s", e)

                    env.teardown()
                    self.__context.pop()

    def wait_for_source_key(self, source_name):
        filesystem_id = self.source_app.crypto_util.hash_codename(source_name)

        def key_available(filesystem_id):
            assert self.source_app.crypto_util.getkey(filesystem_id)

        self.wait_for(lambda: key_available(filesystem_id), timeout=60)

    def create_new_totp(self, secret):
        self.new_totp = pyotp.TOTP(secret)

    def wait_for(self, function_with_assertion, timeout=None):
        """Polling wait for an arbitrary assertion."""
        # Thanks to
        # http://chimera.labs.oreilly.com/books/1234000000754/ch20.html#_a_common_selenium_problem_race_conditions
        if timeout is None:
            timeout = self.timeout

        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                return function_with_assertion()
            except (AssertionError, WebDriverException):
                time.sleep(self.poll_frequency)
        # one more try, which will raise any errors if they are outstanding
        return function_with_assertion()

    def safe_click_by_id(self, element_id):
        """
        Clicks the element with the given ID attribute.

        Returns:
            el: The element, if found.

        Raises:
            selenium.common.exceptions.TimeoutException: If the element cannot be found in time.

        """
        el = WebDriverWait(self.driver, self.timeout, self.poll_frequency).until(
            expected_conditions.element_to_be_clickable((By.ID, element_id))
        )
        el.click()
        return el

    def safe_click_by_css_selector(self, selector):
        """
        Clicks the first element with the given CSS selector.

        Returns:
            el: The element, if found.

        Raises:
            selenium.common.exceptions.TimeoutException: If the element cannot be found in time.

        """
        el = WebDriverWait(self.driver, self.timeout, self.poll_frequency).until(
            expected_conditions.element_to_be_clickable((By.CSS_SELECTOR, selector))
        )
        el.click()
        return el

    def safe_click_all_by_css_selector(self, selector, root=None):
        """
        Clicks each element that matches the given CSS selector.

        Returns:
            els (list): The list of elements that matched the selector.

        Raises:
            selenium.common.exceptions.TimeoutException: If the element cannot be found in time.

        """
        if root is None:
            root = self.driver
        els = self.wait_for(lambda: root.find_elements_by_css_selector(selector))
        for el in els:
            clickable_el = WebDriverWait(self.driver, self.timeout, self.poll_frequency).until(
                expected_conditions.element_to_be_clickable((By.CSS_SELECTOR, selector))
            )
            clickable_el.click()
        return els

    def safe_send_keys_by_id(self, element_id, text):
        """
        Sends the given text to the element with the specified ID.

        Returns:
            el: The element, if found.

        Raises:
            selenium.common.exceptions.TimeoutException: If the element cannot be found in time.

        """
        el = WebDriverWait(self.driver, self.timeout, self.poll_frequency).until(
            expected_conditions.element_to_be_clickable((By.ID, element_id))
        )
        el.send_keys(text)
        return el

    def safe_send_keys_by_css_selector(self, selector, text):
        """
        Sends the given text to the first element with the given CSS selector.

        Returns:
            el: The element, if found.

        Raises:
            selenium.common.exceptions.TimeoutException: If the element cannot be found in time.

        """
        el = WebDriverWait(self.driver, self.timeout, self.poll_frequency).until(
            expected_conditions.element_to_be_clickable((By.CSS_SELECTOR, selector))
        )
        el.send_keys(text)
        return el

    def alert_wait(self, timeout=None):
        if timeout is None:
            timeout = self.timeout * 2
        WebDriverWait(self.driver, timeout, self.poll_frequency).until(
            expected_conditions.alert_is_present(), "Timed out waiting for confirmation popup."
        )

    def alert_accept(self):
        # adapted from https://stackoverflow.com/a/34795883/837471
        def alert_is_not_present(object):
            """ Expect an alert to not be present."""
            try:
                alert = self.driver.switch_to.alert
                alert.text
                return False
            except NoAlertPresentException:
                return True

        self.driver.switch_to.alert.accept()
        WebDriverWait(self.driver, self.timeout, self.poll_frequency).until(
            alert_is_not_present, "Timed out waiting for confirmation popup to disappear."
        )
