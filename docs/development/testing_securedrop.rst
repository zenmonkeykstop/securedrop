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

Description of release process and manual/automated testing during two-week 
phase.

Prerequisites
^^^^^^^^^^^^^
How to set up prod VMs, or use hardware. (staging worth mentioning?)

Getting Started
^^^^^^^^^^^^^^^
Finding the test plan, finding the master release ticket, how to submit 
the plan

Testing clean installs
^^^^^^^^^^^^^^^^^^^^^^
How to install from apt-test, by updating ansible vars


Testing upgrades
^^^^^^^^^^^^^^^^
How to use an ansible playbook to update repo info in an existing install
to point to apt-test

Server and Admin testing
^^^^^^^^^^^^^^^^^^^^^^^^
Server configuration checks:

- how to run them
- expected results

iptables configuration:

- how to check
- ssh-over-tor configuration
- ssh-local configuration

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

