// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

package ecsservicediscovery

import (
	"fmt"
	"log"
	"regexp"
	"strconv"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ecs"
)

const (
	containerNameLabel   = "container_name"
	serviceNameLabel     = "ServiceName"
	taskFamilyLabel      = "TaskDefinitionFamily"
	taskRevisionLabel    = "TaskRevision"
	taskGroupLabel       = "TaskGroup"
	taskStartedbyLabel   = "StartedBy"
	taskLaunchTypeLabel  = "LaunchType"
	taskJobNameLabel     = "job"
	taskMetricsPathLabel = "__metrics_path__"
	ec2InstanceTypeLabel = "InstanceType"
	ec2VpcIdLabel        = "VpcId"
	ec2SubnetIdLabel     = "SubnetId"

	//https://prometheus.io/docs/prometheus/latest/configuration/configuration/#scrape_config
	defaultPrometheusMetricsPath = "/metrics"
)

type EC2MetaData struct {
	ContainerInstanceId string
	ECInstanceId        string
	PrivateIP           string
	InstanceType        string
	VpcId               string
	SubnetId            string
}

type DecoratedTask struct {
	Task           *ecs.Task
	TaskDefinition *ecs.TaskDefinition
	EC2Info        *EC2MetaData
	ServiceName    string

	DockerLabelBased    bool
	TaskDefinitionBased bool
}

func (t *DecoratedTask) String() string {
	return fmt.Sprintf("Task:\n\t\tTaskArn: %v\n\t\tTaskDefinitionArn: %v\n\t\tEC2Info: %v\n\t\tDockerLabelBased: %v\n\t\tTaskDefinitionBased: %v\n",
		aws.StringValue(t.Task.TaskArn),
		aws.StringValue(t.Task.TaskDefinitionArn),
		t.EC2Info,
		t.DockerLabelBased,
		t.TaskDefinitionBased,
	)
}

func addExporterLabels(labels map[string]string, labelKey string, labelValue *string) {
	if aws.StringValue(labelValue) != "" {
		labels[labelKey] = *labelValue
	}
}

// Get the private ip of the decorated task.
// Return "" when fail to get the private ip
func (t *DecoratedTask) getPrivateIp() string {
	if t.TaskDefinition.NetworkMode == nil {
		log.Printf("D! getPrivateIp returning empty string, TaskDefinition.NetworkMode == nil\n")
		return ""
	}

	// AWSVPC: Get Private IP from tasks->attachments (ElasticNetworkInterface -> privateIPv4Address)
	if *t.TaskDefinition.NetworkMode == ecs.NetworkModeAwsvpc {
		for _, v := range t.Task.Attachments {
			if aws.StringValue(v.Type) == "ElasticNetworkInterface" {
				for _, d := range v.Details {
					if aws.StringValue(d.Name) == "privateIPv4Address" {
						log.Printf("D! getPrivateIp awsvpc, returning '%s'\n", aws.StringValue(d.Value))
						return aws.StringValue(d.Value)
					}
				}
			}
		}
	}

	if t.EC2Info != nil {
		log.Printf("D! getPrivateIp, returning t.EC2Info.PrivateIP '%s'\n", t.EC2Info.PrivateIP)
		return t.EC2Info.PrivateIP
	}

	log.Printf("D! getPrivateIp returning empty string\n")
	return ""
}

func (t *DecoratedTask) getPrometheusExporterPort(configuredPort int64, c *ecs.ContainerDefinition) int64 {
	log.Printf("D! getPrometheusExporterPort: %d\n", configuredPort)
	var mappedPort int64 = 0
	networkMode := aws.StringValue(t.TaskDefinition.NetworkMode)
	if networkMode == "" || networkMode == ecs.NetworkModeNone {
		// for network type: none, skipped directly
		log.Printf("D! getPrometheusExporterPort, skipping, no network mode: %d\n", configuredPort)
		return 0
	}

	if networkMode == ecs.NetworkModeAwsvpc || networkMode == ecs.NetworkModeHost {
		// for network type: awsvpc or host, get the mapped port from: taskDefinition->containerDefinitions->portMappings
		for _, v := range c.PortMappings {
			if aws.Int64Value(v.ContainerPort) == configuredPort {
				mappedPort = aws.Int64Value(v.HostPort)
				log.Printf("D! getPrometheusExporterPort, awsvpc/host, configuredPort:mappedPort: %d:%d\n", configuredPort, mappedPort)
			}
		}
	} else if networkMode == ecs.NetworkModeBridge {
		// for network type: bridge, get the mapped port from: task->containers->networkBindings
		containerName := aws.StringValue(c.Name)
		for _, tc := range t.Task.Containers {
			if containerName == aws.StringValue(tc.Name) {
				for _, v := range tc.NetworkBindings {
					if aws.Int64Value(v.ContainerPort) == configuredPort {
						mappedPort = aws.Int64Value(v.HostPort)
						log.Printf("D! getPrometheusExporterPort bridge, configuredPort:mappedPort: %d:%d\n", configuredPort, mappedPort)
					}
				}
			}
		}
	}
	return mappedPort
}

func (t *DecoratedTask) generatePrometheusTarget(
	dockerLabelReg *regexp.Regexp,
	c *ecs.ContainerDefinition,
	ip string,
	mappedPort int64,
	metricsPath string,
	customizedJobName string) *PrometheusTarget {

	labels := make(map[string]string)
	addExporterLabels(labels, containerNameLabel, c.Name)
	addExporterLabels(labels, taskFamilyLabel, t.TaskDefinition.Family)
	revisionStr := fmt.Sprintf("%d", *t.TaskDefinition.Revision)
	addExporterLabels(labels, taskRevisionLabel, &revisionStr)
	addExporterLabels(labels, taskGroupLabel, t.Task.Group)
	addExporterLabels(labels, taskStartedbyLabel, t.Task.StartedBy)
	addExporterLabels(labels, taskLaunchTypeLabel, t.Task.LaunchType)
	if t.EC2Info != nil {
		addExporterLabels(labels, ec2InstanceTypeLabel, &t.EC2Info.InstanceType)
		addExporterLabels(labels, ec2VpcIdLabel, &t.EC2Info.VpcId)
		addExporterLabels(labels, ec2SubnetIdLabel, &t.EC2Info.SubnetId)
	}

	addExporterLabels(labels, taskMetricsPathLabel, &metricsPath)
	for k, v := range c.DockerLabels {
		if dockerLabelReg.MatchString(k) {
			addExporterLabels(labels, k, v)
		}
	}
	// handle customized job label at last, so the conflict job docker label is overriden
	addExporterLabels(labels, taskJobNameLabel, &customizedJobName)

	return &PrometheusTarget{
		Targets: []string{fmt.Sprintf("%s:%d", ip, mappedPort)},
		Labels:  labels,
	}
}

func (t *DecoratedTask) exportDockerLabelBasedTarget(config *ServiceDiscoveryConfig,
	dockerLabelReg *regexp.Regexp,
	ip string,
	c *ecs.ContainerDefinition,
	targets map[string]*PrometheusTarget) {

	if !t.DockerLabelBased {
		log.Printf("D! Skipping,  not DockerLabelBased: %v\n", t)
		return
	}

	configuredPortStr, ok := c.DockerLabels[config.DockerLabel.PortLabel]
	if !ok {
		// skip the container without matching sd_port_label
		log.Printf("D! Skipping, missing sd_port_label: %v\n", c)
		return
	}

	var exporterPort int64
	if port, err := strconv.Atoi(aws.StringValue(configuredPortStr)); err != nil || port < 0 {
		// an invalid port definition.
		log.Printf("D! Skipping, invalid port definition: %s\n", *configuredPortStr)
		return
	} else {
		exporterPort = int64(port)
	}
	mappedPort := t.getPrometheusExporterPort(exporterPort, c)
	if mappedPort == 0 {
		log.Printf("D! Skipping, mappedPort == 0: %v\n", c)
		return
	}

	metricsPath := defaultPrometheusMetricsPath
	metricsPathLabel := ""
	if v, ok := c.DockerLabels[config.DockerLabel.MetricsPathLabel]; ok {
		metricsPath = *v
		metricsPathLabel = *v
	}
	targetKey := fmt.Sprintf("%s:%d%s", ip, mappedPort, metricsPath)
	if _, ok := targets[targetKey]; ok {
		log.Printf("D! Skipping, not ok\n")
		return
	}

	customizedJobName := ""
	if _, ok := c.DockerLabels[config.DockerLabel.JobNameLabel]; ok {
		customizedJobName = *c.DockerLabels[config.DockerLabel.JobNameLabel]
	}

	targets[targetKey] = t.generatePrometheusTarget(dockerLabelReg, c, ip, mappedPort, metricsPathLabel, customizedJobName)
}

func (t *DecoratedTask) exportTaskDefinitionBasedTarget(config *ServiceDiscoveryConfig,
	dockerLabelReg *regexp.Regexp,
	ip string,
	c *ecs.ContainerDefinition,
	targets map[string]*PrometheusTarget) {

	if !t.TaskDefinitionBased {
		log.Printf("D! Skipping, not TaskDefinitionBased: %v\n", t)
		return
	}

	for _, v := range config.TaskDefinitions {
		// skip if task def regex mismatch
		if !v.taskDefRegex.MatchString(*t.Task.TaskDefinitionArn) {
			log.Printf("D! Skipping, '%s' does not match '%s'\n", *t.Task.TaskDefinitionArn, v.taskDefRegex)
			continue
		}

		// skip if there is container name regex pattern configured and container name mismatch
		if v.ContainerNamePattern != "" && !v.containerNameRegex.MatchString(*c.Name) {
			log.Printf("D! Skipping, '%s' does not match '%s'\n", *c.Name, v.containerNameRegex)
			continue
		}

		for _, port := range v.metricsPortList {
			mappedPort := t.getPrometheusExporterPort(int64(port), c)
			if mappedPort == 0 {
				log.Printf("D! Skipping, mappedPort == 0: %v\n", t)
				continue
			}

			metricsPath := defaultPrometheusMetricsPath
			if v.MetricsPath != "" {
				metricsPath = v.MetricsPath
			}
			targetKey := fmt.Sprintf("%s:%d%s", ip, mappedPort, metricsPath)

			if _, ok := targets[targetKey]; ok {
				log.Printf("D! Skipping, not ok\n")
				continue
			}

			targets[targetKey] = t.generatePrometheusTarget(dockerLabelReg, c, ip, mappedPort, v.MetricsPath, v.JobName)
		}

	}
}

func (t *DecoratedTask) exportServiceEndpointBasedTarget(config *ServiceDiscoveryConfig,
	dockerLabelReg *regexp.Regexp,
	ip string,
	c *ecs.ContainerDefinition,
	targets map[string]*PrometheusTarget) {

	if t.ServiceName == "" {
		log.Printf("D! Skipping task with empty ServiceName: %v\n", t)
		return
	}

	for _, v := range config.ServiceNamesForTasks {
		// skip if service name regex mismatch
		if !v.serviceNameRegex.MatchString(t.ServiceName) {
			log.Printf("D! Skipping task ServiceName '%s' does not match '%s'\n", t.ServiceName, v.serviceNameRegex)
			continue
		}

		if v.ContainerNamePattern != "" && !v.containerNameRegex.MatchString(*c.Name) {
			log.Printf("D! Skipping task container name '%s' does not match '%s'\n", *c.Name, v.ContainerNamePattern)
			continue
		}

		for _, port := range v.metricsPortList {
			mappedPort := t.getPrometheusExporterPort(int64(port), c)
			if mappedPort == 0 {
				log.Printf("D! Skipping mappedPort == 0")
				continue
			}

			metricsPath := defaultPrometheusMetricsPath
			if v.MetricsPath != "" {
				metricsPath = v.MetricsPath
			}
			targetKey := fmt.Sprintf("%s:%d%s", ip, mappedPort, metricsPath)

			if _, ok := targets[targetKey]; ok {
				log.Printf("D! Skipping, not ok == 0")
				continue
			}

			prometheusTarget := t.generatePrometheusTarget(dockerLabelReg, c, ip, mappedPort, v.MetricsPath, v.JobName)
			addExporterLabels(prometheusTarget.Labels, serviceNameLabel, &t.ServiceName)
			targets[targetKey] = prometheusTarget
		}
	}

}

func (t *DecoratedTask) ExporterInformation(config *ServiceDiscoveryConfig, dockerLabelRegex *regexp.Regexp, targets map[string]*PrometheusTarget) {
	ip := t.getPrivateIp()
	if ip == "" {
		log.Printf("D! Skipping task with no private IP address: %v\n", t)
		return
	}
	for _, c := range t.TaskDefinition.ContainerDefinitions {
		t.exportServiceEndpointBasedTarget(config, dockerLabelRegex, ip, c, targets)
		t.exportDockerLabelBasedTarget(config, dockerLabelRegex, ip, c, targets)
		t.exportTaskDefinitionBasedTarget(config, dockerLabelRegex, ip, c, targets)
	}
}
