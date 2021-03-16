#!/bin/bash

. /opt/openenclave/share/openenclave/openenclaverc
make
python3.7 -c "import simple; simple.start_server()"
