package ssm

import (
	"github.com/aws/amazon-cloudwatch-agent/tool/data"
	"github.com/aws/amazon-cloudwatch-agent/tool/processors"
	"github.com/aws/amazon-cloudwatch-agent/tool/runtime"

	"time"

	"github.com/aws/amazon-cloudwatch-agent/tool/util"

	"fmt"

	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ssm"
)

const (
	ErrCodeAccessDeniedException = "AccessDeniedException"
	defaultRetryCount            = 1 //total attempts are defaultRetryCount+1
)

var Processor processors.Processor = &processor{}

type processor struct{}

func (p *processor) Process(ctx *runtime.Context, config *data.Config) {
	answer := util.Yes("Do you want to store the config in the SSM parameter store?")
	if !answer {
		return
	}

	serializedConfig := util.ReadConfigFromJsonFile()
	parameterStoreName := determineParameterStoreName(ctx)
	region := determineRegion(ctx)

	var err error
	for i := 0; i <= defaultRetryCount; i++ {
		creds := determineCreds(ctx)
		err = sendConfigToParameterStore(serializedConfig, parameterStoreName, region, creds)
		if err == nil {
			fmt.Printf("Successfully put config to parameter store %s.\n", parameterStoreName)
			return
		}

		if awsErr, ok := err.(awserr.Error); ok {
			switch awsErr.Code() {
			case ErrCodeAccessDeniedException:
				fmt.Printf("Please make sure the creds you used have the right permissions configured for SSM access.\n")
				continue
			default:
				fmt.Printf("Error code: %s, message: %s, original error: %v\n", awsErr.Code(), awsErr.Message(), awsErr.OrigErr())
			}
		}
		break
	}
	fmt.Printf("Error in putting config to parameter store %s: %v\n", parameterStoreName, err)
}

func (p *processor) NextProcessor(ctx *runtime.Context, config *data.Config) interface{} {
	return nil
}

func determineCreds(ctx *runtime.Context) *credentials.Credentials {
	accessKeys := []string{}
	sdkAccessKey, _, sdkCreds := util.SDKCredentials()
	sdkAccessKeyDesc := ""
	if sdkCreds != nil {
		sdkAccessKeyDesc = sdkAccessKey + "(From SDK)"
		accessKeys = append(accessKeys, sdkAccessKeyDesc)
	}

	fileAccessKey := ""
	fileAccessKeyDesc := ""
	var fileCredentialsProvider *credentials.Credentials
	fileCredentialsProvider = credentials.NewSharedCredentials("", "AmazonCloudWatchAgent")
	fileCreds, err := fileCredentialsProvider.Get()
	if err == nil {
		fileAccessKey = fileCreds.AccessKeyID
		fileAccessKeyDesc = fileAccessKey + "(From Profile: AmazonCloudWatchAgent)"
		accessKeys = append(accessKeys, fileAccessKeyDesc)
	}

	if len(accessKeys) > 0 {
		accessKeys = append(accessKeys, "Other")

		answer := util.Choice("Which AWS credential should be used to send json config to parameter store?", 1, accessKeys)
		if answer == sdkAccessKeyDesc {
			return sdkCreds
		} else if answer == fileAccessKeyDesc {
			return fileCredentialsProvider
		}
	}
	return askCreds()
}

func askCreds() *credentials.Credentials {
	accessKey := util.Ask("Please provide credentials to upload the json config file to parameter store.\nAWS Access Key:")
	secretKey := util.Ask("AWS Secret Key:")
	creds := credentials.NewStaticCredentials(accessKey, secretKey, "")
	return creds
}

func determineParameterStoreName(ctx *runtime.Context) string {
	defaultParameterStoreName := "AmazonCloudWatch-" + ctx.OsParameter
	parameterStoreName := util.AskWithDefault("What parameter store name do you want to use to store your config? (Use 'AmazonCloudWatch-' prefix if you use our managed AWS policy)", defaultParameterStoreName)
	return parameterStoreName
}

func determineRegion(ctx *runtime.Context) string {
	var region string
	if !ctx.IsOnPrem {
		region = util.DefaultEC2Region()
	} else {
		region = util.SDKRegionWithProfile("AmazonCloudWatchAgent")
	}
	if region == "" {
		region = "us-east-1"
	}
	region = util.AskWithDefault("Which region do you want to store the config in the parameter store?", region)
	return region
}

func sendConfigToParameterStore(config, parameterStoreName, region string, creds *credentials.Credentials) error {
	awsConfig := aws.NewConfig().WithRegion(region)
	if creds != nil {
		awsConfig = awsConfig.WithCredentials(creds)
	}
	ses, err := session.NewSession(awsConfig)
	if err != nil {
		fmt.Printf("Error in creating session:\n %v\n", err)
		return err
	}
	ssmClient := ssm.New(ses)
	input := ssm.PutParameterInput{}
	input.SetName(parameterStoreName)
	input.SetOverwrite(true)
	hostName, _ := os.Hostname()
	input.SetDescription(fmt.Sprintf("Generated by wizard on %s at %s", hostName, time.Now().Format(time.RFC1123)))
	input.SetType("String")
	input.SetValue(config)
	_, err = ssmClient.PutParameter(&input)
	return err
}
