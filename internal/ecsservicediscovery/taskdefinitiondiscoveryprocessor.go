// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

package ecsservicediscovery

import (
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ecs"
)

// Tag the Tasks that match the Task Definition ARN based Service Discovery
type TaskDefinitionDiscoveryProcessor struct {
	taskDefsConfig []*TaskDefinitionConfig
}

func NewTaskDefinitionDiscoveryProcessor(taskDefinitions []*TaskDefinitionConfig) *TaskDefinitionDiscoveryProcessor {
	for _, v := range taskDefinitions {
		v.init()
	}

	return &TaskDefinitionDiscoveryProcessor{taskDefsConfig: taskDefinitions}
}

func checkContainerNamePattern(containers []*ecs.ContainerDefinition, config *TaskDefinitionConfig) bool {
	for _, c := range containers {
		if config.containerNameRegex.MatchString(aws.StringValue(c.Name)) {
			return true
		}
		log.Printf("D! Container name pattern did not match: '%s' \n", aws.StringValue(c.Name))
	}
	return false
}

func (p *TaskDefinitionDiscoveryProcessor) Process(cluster string, taskList []*DecoratedTask) ([]*DecoratedTask, error) {
	if len(p.taskDefsConfig) == 0 {
		return taskList, nil
	}

	for _, v := range taskList {
		if v.TaskDefinition.TaskDefinitionArn == nil {
			continue
		}
		for _, t := range p.taskDefsConfig {
			if t.taskDefRegex.MatchString(aws.StringValue(v.TaskDefinition.TaskDefinitionArn)) {
				log.Printf("D! TaskDefinitionArn '%s' matches: '%s' \n", aws.StringValue(v.TaskDefinition.TaskDefinitionArn), t.taskDefRegex)
				if t.ContainerNamePattern == "" || checkContainerNamePattern(v.TaskDefinition.ContainerDefinitions, t) {
					v.TaskDefinitionBased = true
					break
				}
			} else {
				log.Printf("D! TaskDefinitionArn '%s' not matches: '%s' \n", aws.StringValue(v.TaskDefinition.TaskDefinitionArn), t.taskDefRegex)
			}
		}
	}

	return taskList, nil
}

func (p *TaskDefinitionDiscoveryProcessor) ProcessorName() string {
	return "TaskDefinitionDiscoveryProcessor"
}
