#!/bin/bash
TOOLS=`dirname $0`
VENV=$TOOLS/../.melange-venv
source $VENV/bin/activate && $@
