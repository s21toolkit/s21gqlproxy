#!/bin/sh

sudo trust anchor --store certs/mitmproxy-ca-cert.cer
sudo update-ca-trust -v