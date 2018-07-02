HPNAPY
===========
HPNAPY is a Python3 library to access and interface with HP Network Automation's SOAP API.

## Usage

Here is an example of connecting through the API and retrieving a list of device groups.
```
from hpnapy import NAInterface

# Initialize our interface
hpna = NAInterface("https://foo.bar")
hpna.login('username', 'password')

# Retrieve and iterate a list of device groups
device_groups = hpna.list_device_group()
for entry in device_groups:
    print(entry)

```

We can globally disable SSL verification to prevent errors and messaging. This is not recommended as this is a potential security concern.
```
from hpnapy import NAInterface

# Initialize our interface
hpna = NAInterface("https://foo.bar", ssl_verify=False)

```

In order to filter results, we can pass filter keys as defined in the HPE Network Automation Software (NA) CLI/API Command Reference.

```
from hpnapy import NAInterface

# Initialize our interface
hpna = NAInterface("https://foo.bar")
hpna.login('username', 'password')

# Retrieve and iterate a list of device groups
filtered_devices = hpna.list_device(vendor="Cisco", group="My Cisco Switches Group")
for entry in filtered_devices:
    print(entry)

```

## Exceptions

This library uses its own set of exceptions.

```
hpnapy.exceptions.HPNAConnectionError
hpnapy.exceptions.HPNAQueryParamError
hpnapy.exceptions.HPNAQueryError
```

### Contributing ###

Spencer Ervin ([spenceation](https://github.com/spenceation)) is the creator and current maintainers of the hpnapy library.

Pull requests are always welcome. Before submitting a pull request, please ensure that your coding style follows PEP 8.

### Legal ###

Licensed under the GNU General Public License v3.0; you may not use this file except in compliance with the License. You may obtain a copy of the License at

    https://www.gnu.org/licenses/gpl-3.0.en.html
