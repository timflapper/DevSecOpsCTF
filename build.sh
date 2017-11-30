#!/bin/sh
cd lambda
pip3 install ruamel.yaml -t .
zip -r devsecops_starter.zip *
