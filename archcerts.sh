#!/bin/sh

sudo trust anchor --store config/mitmproxy-ca-cert.cer
sudo update-ca-trust -v