Testing SecureDrop
==================

The SecureDrop project ships both application code for running on servers
hosted on-site at news organizations, as well as configuration scripts
for provisioning the servers to accept updates to the application code,
and to harden the system state. Therefore testing for the project includes
:ref:`Application Tests<app_tests>` for validating that the app code behaves
as expected, and :ref:`Configuration Tests<config_tests>` to ensure that the
servers are appropriately locked down, and able to accept updates to the app code.

In addition, the :ref:`Continuous Integration<ci_tests>` automatically runs
the above Application and Configuration tests against cloud hosts,
to aid in PR review.

Release testing
---------------

SecureDrop's regular release schedule is linked to that of Tails, due to 
*Admin Workstation* dependencies. In practice, this means that a new minor 
version of SecureDrop is released every 9-10 weeks. Patch versions are released
as needed outside of this schedule. These point releases are usually in response
to security issues or other critical bugs.

The regular release process begins 2 weeks before the release date, with a freeze 
on new features. In the first week, changelog and initial test plan are written by the designated
release manager, and manual testing begins on release candidate builds. If there
are new localization strings that have not yet been translated, the release 
manager coordinates with the volunteer translator community to get any changes 
added via Weblate. 

At the beginning of the second week, a freeze is imposed on new strings, with an 
absolute deadline of the day before release for any final additions.

If a release includes a kernel update, the release manager also creates a QA testing
matrix, with columns covering kernel-specific tests including testing for grsec settings
and cpu vulnerabilities for each supported hardware configuration. 

Prerequisites
^^^^^^^^^^^^^
Manual QA should be performed against :ref:`prod VMs<production_vms>` or 
:ref:`hardware instances<hardware_guide>`. The testing process covers both fresh installs and
upgrades from the latest version of SecureDrop.

Getting Started
^^^^^^^^^^^^^^^
You can find links to the current release's test plan in Github, in the Master 
Release Ticket - for example, here is the `release ticket for 0.11.0 <https://github.com/freedomofpress/securedrop/issues/3946>`_.

Fresh Install Setup
^^^^^^^^^^^^^^^^^^^
To set up  the fresh install scenario, you should first follow the SecureDrop install process as far as the step where Ubuntu is installed on the *Application* and *Monitor Servers*. In the case of testing against prod vms, this would mean going as far as: ``vagrant up --no-provision /prod/`` 

Then, on the *Admin Workstation*, you should check out the tag corresponding to 
the release candidate that you'd like to test. For example:

.. code:: sh

    cd ~/Persistent/securedrop
    git checkout 0.11.0-rc4    

Having checked out the RC tag, you should now modify the Ansible playbook used to install SecureDrop to use the FPF test APT repo instead of the production repo. In the file ``~/Persistent/securedrop/install_files/ansible-base/roles/install-fpf-repo/defaults/main.yml``, change the value of the ``apt_repo_url``
variable from:

.. code:: sh

   apt_repo_url: https://apt.freedom.press

to:

.. code:: sh

   apt_repo_url: https://apt-test.freedom.press

In the same file, replace the FPF repo signing key with its test counterpart by 
updating the following section from:

.. code:: sh

    apt_repo_pubkey_files:
      - fpf-signing-key.pub

to:

.. code:: sh

    apt_repo_pubkey_files:
      - apt-test-signing-key.pub

If the release contains a Tor update, you should also change the ``tor_apt_repo_url``
variable in ``~/Persistent/securedrop/install_files/ansible-base/group_vars/all/securedrop`` from:

.. code:: sh
    
    tor_apt_repo_url: https://tor-apt.freedom.press

to:


.. code:: sh
    
    tor_apt_repo_url: https://apt-test.freedom.press


Then, proceed with the installation as normal. When the installation and Tails configuration is complete, you 
can check the version information in the footer on the *Source Interface* to quickly 
verify that you are running the expected release candidate version.

Upgrade Setup
^^^^^^^^^^^^^
To set up an environment to test the upgrade scenario, you should first install the latest release version of SecureDrop on your chosen environment.

Server and Admin testing
^^^^^^^^^^^^^^^^^^^^^^^^
You'll need to use the *Admin Workstation*, after successfully running the 
`./securedrop-admin tailsconfig` command, to test the server configuration:

- verify that the *Journalist* and *Source* interfaces are up using the appropriate
  desktop shortcuts
- verify that you can SSH into the servers from a terminal using the commands 
  `ssh app` and `ssh mon`
- on each server, use the command `sudo aa-status` to check that AppArmor is loaded
- on each server, use the command `uname -r` to check the kernel version and 
  verify the `-grsec` suffix
- on each server, check iptables rules using the command `sudo iptables -L -n`
  (expected output examples TK)

To test the CLI management script and add an initial admin user, from an ssh 
session on the app server, run:

.. code:: sh

  sudo -u www-data bash
  cd /var/www/securedrop
  ./manage.py add-admin # follow script instructions, choosing N for Yubikey setup.

Then use the login credentials created to log in to the Journalist Interface.
 
iptables configuration:

- how to check
- ssh-over-tor vs ssh-over-lan

Admin and CLI  testing

Application acceptance testing
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Overview and gotchas

Tails testing
^^^^^^^^^^^^^
Testing the SD Updater

Release-specific testing
^^^^^^^^^^^^^^^^^^^^^^^^
Hard to know what to put here as impossible to predict what will be worked on
- where to find test plans for new features (in issues)
- where to find help (Gitter, forum)

Preflight checks
^^^^^^^^^^^^^^^^
Rationale for testing installs, upgrades from apt rather than apt-test for 
"final" packages. Brief description of test steps. 

