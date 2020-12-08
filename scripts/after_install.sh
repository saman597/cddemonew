#!/bin/bash

sudo chmod -R 757 /opt/codedeploy-agent
sudo chmod -R 757 /home/ec2-user/nodejs
cd /home/ec2-user/nodejs
npm -v
whereis npm
npm install