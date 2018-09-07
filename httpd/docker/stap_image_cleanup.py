# Note that this script was written to be executable by either version
# of python (checked by running pylint-2 and pylint-3 on it). Also
# note that the python version this script gets executed by is decided
# on by httpd/backends.cxx.

"""Build a docker file and container image based on a JSON template."""

from __future__ import print_function
import subprocess
import sys
import json
import re
import datetime

def _eprint(*args, **kwargs):
    """Print to stderr."""
    print(*args, file=sys.stderr, **kwargs)

def main():
    """Main function."""
    try:
        raw_json = subprocess.check_output(["buildah", "images", "--json"])
    except subprocess.CalledProcessError as err:
        _eprint('buildah images failed: %s' % err)
        sys.exit(1)

    try:
        images_json = json.loads(raw_json)
    except ValueError as err:
        _eprint("Error: Invalid JSON input: %s" % err)
        sys.exit(1)

    _eprint(images_json)
    name_regexp = re.compile(r'^sourceware.org/[a-f\d_]+/[a-f\d]+:(\d+)$')

    # print the keys and values
    for item in images_json:
        #print("The item is ({})".format(item))
        if not isinstance(item, dict):
            _eprint("Expected a json dict, got a %s" % type(item))
            continue

        for key in item:
            value = item[key]
            if key != "names":
                continue

            # The value of 'names' should be a list of names for this
            # image.
            if not isinstance(value, list):
                _eprint("Expected a json list, got a %s" % type(value))
                continue

            for name in value:
                match = name_regexp.match(name)
                if match:
                    date_str = match.group(1)
                    print("full name: %s, date: %s" % (name, date_str))

                    # Convert the date string into a numeric date/time.
                    dt_then = datetime.datetime.strptime(date_str, "%Y%m%d%H%M")
                    dt_now = datetime.datetime.utcnow()

                    # If for some reason the image date is in the
                    # future, skip it.
                    if dt_then >= dt_now:
                        continue

                    time_delta = dt_now - dt_then
                    two_days = datetime.timedelta(days=2)
                    if time_delta > two_days:
                        if subprocess.call(["buildah", "rmi", name]) == 0:
                            print("Remove %s" % name)
                        else:
                            _eprint("Error removing image %s" % name)
            print("")
    sys.exit(0)

if __name__ == '__main__':
    main()
