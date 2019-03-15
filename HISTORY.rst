.. :changelog:

History
=======

1.0.6
-----

- Added: New API commands supported:

  - add_change_plan
  - del_change_plan
  - deploy_change_plan
  - list_change_plan
  - mod_change_plan
  - reboot_device
  - show_change_plan
  - show_rule_compliance
  - synchronize

- Fix: HTTP status code 221 causing exception.

1.0.5
-----

Released: 2019-02-19

- Fix: HTTP status code 501 causing exception.
- Fix: HTTP status code 204 causing exception.
- Fix: show_policy_compliance was returning a single result when multiple results where expected.