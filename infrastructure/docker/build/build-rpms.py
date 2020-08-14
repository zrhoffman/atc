#!/usr/bin/env python3
from compose.cli.main import TopLevelCommand, project_from_options
from compose.container import Container
from compose.project import Project
from compose.service import Service
import os

buildDirectory = os.path.dirname(os.path.realpath(__file__))
dockerCompose = TopLevelCommand(project_from_options(buildDirectory, {}))
project: Project
project = dockerCompose.project
service: Service
services = [service.name for service in project.services if service.name != 'weasel']

dockerCompose.up({'SERVICE': services,
                  '--attach-dependencies': False,
                  '--abort-on-container-exit': False,
                  '--always-recreate-deps': False,
                  '--build': False,
                  '--detach': False,
                  '--force-recreate': False,
                  '--no-build': False,
                  '--no-color': False,
                  '--no-deps': False,
                  '--no-recreate': False,
                  '--no-start': False,
                  '--remove-orphans': False,
                  '--scale': ['=1'],
                  })
containers = project.containers(service_names=services, stopped=True)

container: Container
failedBuilds = [container.service for container in containers if container.exit_code != 0]
failedBuildCount = len(failedBuilds)

if failedBuildCount == 0:
    message = 'All components built successfully!'
    exitCode = 0
    components = [container.service for container in containers]
else:
    message = '{} component{} failed to build:'.format(failedBuildCount, '' if failedBuildCount == 1 else 's')
    exitCode = 1
    components = failedBuilds

components.sort()
print('{}\n{}'.format(message, '\n'.join(components)))
exit(exitCode)
