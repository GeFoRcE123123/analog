#!/bin/bash
# Автоматическое исправление прав Docker
sudo usermod -aG docker $USER
newgrp docker
