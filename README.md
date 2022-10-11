# Create/Launch an AWS EC2 instance via AWS CLI

**AWS CLI** (Command Line Interface) is a unified tool for running and managing your various AWS services

This hands-on document is to tell you how to manually create AWS EC2 instance step-by-step

# Detail Procedures:
### Download and install the AWS CLI tool
- Windows:
```
https://awscli.amazonaws.com/AWSCLIV2-version.number.msi
```
- MacOS:
```
https://awscli.amazonaws.com/AWSCLIV2.pkg
```
- Linux:
```
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
```
- Docker:
```
docker run --rm -it amazon/aws-cli command
```

### Create AWS configration
>aws configure
```json
aws configure
AWS Access Key ID [None]: <Your_AWS_Access_Key_ID>
AWS Secret Access Key [None]: <Your_AWS_Secret_Access_Key>
Default region name [None]: us-east-2
Default output format [None]: json
```
### Creating a VPC
- VPC(virtual private cloud) under which an EC2 instance will be launched
```json
aws ec2 create-vpc --cidr-block 10.0.0.0/16
{                                                                      
    "Vpc": {                                                           
        "CidrBlock": "10.0.0.0/16",                                    
        "DhcpOptionsId": "dopt-09985c8746d3b7caa",                     
        "State": "pending",                                            
        "VpcId": "vpc-086e117465fe2d995",                              
        "OwnerId": "<your_owner_id>",                                     
        "InstanceTenancy": "default",                                  
        "Ipv6CidrBlockAssociationSet": [],                             
        "CidrBlockAssociationSet": [                                   
            {                                                          
                "AssociationId": "vpc-cidr-assoc-04092657de005ee9e",   
                "CidrBlock": "10.0.0.0/16",                            
                "CidrBlockState": {                                    
                    "State": "associated"                              
                }                                                      
            }                                                          
        ],                                                             
        "IsDefault": false                                             
    }                                                                  
}
```
VpcId: "vpc-086e117465fe2d995"

### Creating Subnets
- create two subnets one as private and one as public
>aws ec2 create-subnet --vpc-id <vpcId> --cidr-block 10.0.1.0/24
```json
aws ec2 create-subnet --vpc-id vpc-086e117465fe2d995 --cidr-block 10.0.1.0/24
{
    "Subnet": {
        "AvailabilityZone": "us-east-2a",
        "AvailabilityZoneId": "use2-az1",
        "AvailableIpAddressCount": 251,
        "CidrBlock": "10.0.1.0/24",
        "DefaultForAz": false,
        "MapPublicIpOnLaunch": false,
        "State": "available",
        "SubnetId": "subnet-0645b14b8bcad08a9",
        "VpcId": "vpc-086e117465fe2d995",
        "OwnerId": "<your_owner_id>",
        "AssignIpv6AddressOnCreation": false,
        "Ipv6CidrBlockAssociationSet": [],
        "SubnetArn": "arn:aws:ec2:us-east-2:<your_owner_id>:subnet/subnet-0645b14b8bcad08a9",
        "EnableDns64": false,
        "Ipv6Native": false,
        "PrivateDnsNameOptionsOnLaunch": {
            "HostnameType": "ip-name",
            "EnableResourceNameDnsARecord": false,
            "EnableResourceNameDnsAAAARecord": false
        }
    }
}
```
SubnetId: "subnet-0645b14b8bcad08a9"

>aws ec2 create-subnet --vpc-id <vpcId> --cidr-block 10.0.0.0/24
```json
aws ec2 create-subnet --vpc-id vpc-086e117465fe2d995 --cidr-block 10.0.0.0/24
{
    "Subnet": {
        "AvailabilityZone": "us-east-2a",
        "AvailabilityZoneId": "use2-az1",
        "AvailableIpAddressCount": 251,
        "CidrBlock": "10.0.0.0/24",
        "DefaultForAz": false,
        "MapPublicIpOnLaunch": false,
        "State": "available",
        "SubnetId": "subnet-0761518e281b46a6f",
        "VpcId": "vpc-086e117465fe2d995",
        "OwnerId": "<your_owner_id>",
        "AssignIpv6AddressOnCreation": false,
        "Ipv6CidrBlockAssociationSet": [],
        "SubnetArn": "arn:aws:ec2:us-east-2:<your_owner_id>:subnet/subnet-0761518e281b46a6f",
        "EnableDns64": false,
        "Ipv6Native": false,
        "PrivateDnsNameOptionsOnLaunch": {
            "HostnameType": "ip-name",
            "EnableResourceNameDnsARecord": false,
            "EnableResourceNameDnsAAAARecord": false
        }
    }
}
```
SubnetId: "subnet-0761518e281b46a6f"  
make this subnet as public and accessible from the internet later

### Creating Internet Gateway
- **Internet gateway** is used by the private subnet to access the internet for its updates and other packages installations
aws ec2 create-internet-gateway
```json
aws ec2 create-internet-gateway
{
    "InternetGateway": {
        "Attachments": [],
        "InternetGatewayId": "igw-0a7db645e4bb13b63",
        "OwnerId": "<your_owner_id>",
        "Tags": []
    }
}
```
InternetGatewayId: "igw-0a7db645e4bb13b63"
- After the internet gateway is created, note the InternetGatewayId and to attach this internet gateway to the already created VPC
>aws ec2 attach-internet-gateway --vpc-id <vpcId> --internet-gateway-id <InternetGatewayId>
```
aws ec2 attach-internet-gateway --vpc-id vpc-086e117465fe2d995 --internet-gateway-id igw-0a7db645e4bb13b63
```

### Creating Route Table
- create a route table and assigning it to the already created VPC
>aws ec2 create-route-table --vpc-id <vpcId>
```json
aws ec2 create-route-table --vpc-id vpc-086e117465fe2d995
{
    "RouteTable": {
        "Associations": [],
        "PropagatingVgws": [],
        "RouteTableId": "rtb-07f8e3fa7d22acd11",
        "Routes": [
            {
                "DestinationCidrBlock": "10.0.0.0/16",
                "GatewayId": "local",
                "Origin": "CreateRouteTable",
                "State": "active"
            }
        ],
        "Tags": [],
        "VpcId": "vpc-086e117465fe2d995",
        "OwnerId": "<your_owner_id>"
    }
}
```
RouteTableId: "rtb-07f8e3fa7d22acd11"  
- Assign the route to this route table
>aws ec2 create-route --route-table-id <RouteTableId> 
              --destination-cidr-block 0.0.0.0/0 --gateway-id <InternetGatewayId>
```json
aws ec2 create-route --route-table-id rtb-07f8e3fa7d22acd11 --destination-cidr-block 0.0.0.0/0 --gateway-id igw-0a7db645e4bb13b63
{
    "Return": true
}
```

### Viewing the Route Table and Subnets
>aws ec2 describe-route-tables --route-table-id <RouteTableId>
```json
aws ec2 describe-route-tables --route-table-id rtb-07f8e3fa7d22acd11
{
    "RouteTables": [
        {
            "Associations": [],
            "PropagatingVgws": [],
            "RouteTableId": "rtb-07f8e3fa7d22acd11",
            "Routes": [
                {
                    "DestinationCidrBlock": "10.0.0.0/16",
                    "GatewayId": "local",
                    "Origin": "CreateRouteTable",
                    "State": "active"
                },
                {
                    "DestinationCidrBlock": "0.0.0.0/0",
                    "GatewayId": "igw-0a7db645e4bb13b63",
                    "Origin": "CreateRoute",
                    "State": "active"
                }
            ],
            "Tags": [],
            "VpcId": "vpc-086e117465fe2d995",
            "OwnerId": "<your_owner_id>"
        }
    ]
}
```

>aws ec2 describe-subnets --filters "Name=vpc-id,Values=<vpcId>"
    --query "Subnets[*].{ID:SubnetId,CIDR:CidrBlock}"
```json
aws ec2 describe-subnets --filters "Name=vpc-id,Values=vpc-086e117465fe2d995" --query "Subnets[*].{ID:SubnetId,CIDR:CidrBlock}"
[
    {
        "ID": "subnet-0761518e281b46a6f",
        "CIDR": "10.0.0.0/24"
    },
    {
        "ID": "subnet-0645b14b8bcad08a9",
        "CIDR": "10.0.1.0/24"
    }
]
```

### Associating Route Table and modifying subnet 
- Associate the route table with the subnet and making the same subnet as public by mapping the public IP address to it. 
aws ec2 associate-route-table --subnet-id <SubnetId> --route-table-id <RouteTableId>
```json
aws ec2 associate-route-table --subnet-id subnet-0761518e281b46a6f --route-table-id rtb-07f8e3fa7d22acd11
{
    "AssociationId": "rtbassoc-078b0029f6ef6c9e2",
    "AssociationState": {
        "State": "associated"
    }
}
```

>aws ec2 modify-subnet-attribute --subnet-id <SubnetId> --map-public-ip-on-launch
```
aws ec2 modify-subnet-attribute --subnet-id subnet-0761518e281b46a6f --map-public-ip-on-launch
```

### Creating Key Pair and Security Group

>aws ec2 create-key-pair --key-name AWS-EC2-demo-Keypair --query "KeyMaterial" 
                        --output text > "C:\Users\projs\AWS_EC2_Demo_Keypair.pem"
```json
aws ec2 create-key-pair --key-name AWS-EC2-demo-Keypair --query "KeyMaterial" --output text > "C:\Users\projs\AWS_EC2_Demo_Keypair.pem"

ls AWS_EC2_Demo_Keypair.pem
AWS_EC2_Demo_Keypair.pem

aws ec2 describe-key-pairs --key-name AWS-EC2-demo-Keypair
{
    "KeyPairs": [
        {
            "KeyPairId": "key-0cb03b85f445d0ea5",
            "KeyFingerprint": "9d:f8:a4:1c:53:1f:3e:52:74:d6:40:35:d5:99:6b:6b:73:ca:de:77",
            "KeyName": "AWS-EC2-demo-Keypair",
            "KeyType": "rsa",
            "Tags": [],
            "CreateTime": "2022-10-06T18:46:54+00:00"
        }
    ]
}
```

>aws ec2 create-security-group --group-name <security-group-name> 
							  --description "<description>"
                              --vpc-id <vpcId>
```json
aws ec2 create-security-group --group-name DEMO-SG --description "Demo Security group to create EC2 instance" --vpc-id vpc-086e117465fe2d995
{
    "GroupId": "sg-02bf67daf0b0df37e"
}
```
GroupId: "sg-02bf67daf0b0df37e"

>aws ec2 authorize-security-group-ingress --group-id <GroupId> 
            --protocol tcp --port 22 --cidr 0.0.0.0/0
```json
aws ec2 authorize-security-group-ingress --group-id sg-02bf67daf0b0df37e --protocol tcp --port 22 --cidr 0.0.0.0/0
{
    "Return": true,
    "SecurityGroupRules": [
        {
            "SecurityGroupRuleId": "sgr-04d6696c05f9111ac",
            "GroupId": "sg-02bf67daf0b0df37e",
            "GroupOwnerId": "<your_owner_id>",
            "IsEgress": false,
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "CidrIpv4": "0.0.0.0/0"
        }
    ]
}
```

### Running the EC2 Instance
- to run the EC2 Instance, you will need an AMI(Amazon Machine Image) image ID
```
aws ec2 run-instances --image-id <ami-id> --count 1 --instance-type t2.micro  
                       --key-name <Keypair-name>   
                       --security-group-ids <SecurityGroupId>   
                       --subnet-id <SubnetId>  
```                       
```json
aws ec2 run-instances --image-id ami-0d5bf08bc8017c83b --count 1 --instance-type t2.micro --key-name AWS-EC2-demo-Keypair --security-group-ids sg-02bf67daf0b0df37e --subnet-id subnet-0761518e281b46a6f
{
    "Groups": [],
    "Instances": [
        {
            "AmiLaunchIndex": 0,
            "ImageId": "ami-0d5bf08bc8017c83b",
            "InstanceId": "i-0252fb4f6c4e3ba17",
            "InstanceType": "t2.micro",
            "KeyName": "AWS-EC2-demo-Keypair",
            "LaunchTime": "2022-10-06T19:54:04+00:00",
            "Monitoring": {
                "State": "disabled"
            },
            "Placement": {
                "AvailabilityZone": "us-east-2a",
                "GroupName": "",
                "Tenancy": "default"
            },
            "PrivateDnsName": "ip-10-0-0-165.us-east-2.compute.internal",
            "PrivateIpAddress": "10.0.0.165",
            "ProductCodes": [],
            "PublicDnsName": "",
            "State": {
                "Code": 0,
                "Name": "pending"
            },
            "StateTransitionReason": "",
            "SubnetId": "subnet-0761518e281b46a6f",
            "VpcId": "vpc-086e117465fe2d995",
            "Architecture": "x86_64",
            "BlockDeviceMappings": [],
            "ClientToken": "4b977177-4ac9-4775-9945-23e2b6cc89d9",
            "EbsOptimized": false,
            "EnaSupport": true,
            "Hypervisor": "xen",
            "NetworkInterfaces": [
                {
                    "Attachment": {
                        "AttachTime": "2022-10-06T19:54:04+00:00",
                        "AttachmentId": "eni-attach-05a1108df9cba083e",
                        "DeleteOnTermination": true,
                        "DeviceIndex": 0,
                        "Status": "attaching",
                        "NetworkCardIndex": 0
                    },
                    "Description": "",
                    "Groups": [
                        {
                            "GroupName": "DEMO-SG",
                            "GroupId": "sg-02bf67daf0b0df37e"
                        }
                    ],
                    "Ipv6Addresses": [],
                    "MacAddress": "02:17:6d:93:61:64",
                    "NetworkInterfaceId": "eni-0ff61a8cde0757296",
                    "OwnerId": "<your_owner_id>",
                    "PrivateIpAddress": "10.0.0.165",
                    "PrivateIpAddresses": [
                        {
                            "Primary": true,
                            "PrivateIpAddress": "10.0.0.165"
                        }
                    ],
                    "SourceDestCheck": true,
                    "Status": "in-use",
                    "SubnetId": "subnet-0761518e281b46a6f",
                    "VpcId": "vpc-086e117465fe2d995",
                    "InterfaceType": "interface"
                }
            ],
            "RootDeviceName": "/dev/sda1",
            "RootDeviceType": "ebs",
            "SecurityGroups": [
                {
                    "GroupName": "DEMO-SG",
                    "GroupId": "sg-02bf67daf0b0df37e"
                }
            ],
            "SourceDestCheck": true,
            "StateReason": {
                "Code": "pending",
                "Message": "pending"
            },
            "VirtualizationType": "hvm",
            "CpuOptions": {
                "CoreCount": 1,
                "ThreadsPerCore": 1
            },
            "CapacityReservationSpecification": {
                "CapacityReservationPreference": "open"
            },
            "MetadataOptions": {
                "State": "pending",
                "HttpTokens": "optional",
                "HttpPutResponseHopLimit": 1,
                "HttpEndpoint": "enabled",
                "HttpProtocolIpv6": "disabled",
                "InstanceMetadataTags": "disabled"
            },
            "EnclaveOptions": {
                "Enabled": false
            },
            "PrivateDnsNameOptions": {
                "HostnameType": "ip-name",
                "EnableResourceNameDnsARecord": false,
                "EnableResourceNameDnsAAAARecord": false
            },
            "MaintenanceOptions": {
                "AutoRecovery": "default"
            }
        }
    ],
    "OwnerId": "<your_owner_id>",
    "ReservationId": "r-01fb8da8caa99b0b1"
}
```
InstanceId": "i-0252fb4f6c4e3ba17"


- after the instance status is “running” type the command to view the complete details of the EC2 instance that you just created
>aws ec2 describe-instances --instance-id <InstanceId>
```json
aws ec2 describe-instances --instance-id i-0252fb4f6c4e3ba17
{
    "Reservations": [
        {
            "Groups": [],
            "Instances": [
                {
                    "AmiLaunchIndex": 0,
                    "ImageId": "ami-0d5bf08bc8017c83b",
                    "InstanceId": "i-0252fb4f6c4e3ba17",
                    "InstanceType": "t2.micro",
                    "KeyName": "AWS-EC2-demo-Keypair",
                    "LaunchTime": "2022-10-06T19:54:04+00:00",
                    "Monitoring": {
                        "State": "disabled"
                    },
                    "Placement": {
                        "AvailabilityZone": "us-east-2a",
                        "GroupName": "",
                        "Tenancy": "default"
                    },
                    "PrivateDnsName": "ip-10-0-0-165.us-east-2.compute.internal",
                    "PrivateIpAddress": "10.0.0.165",
                    "ProductCodes": [],
                    "PublicDnsName": "",
                    "PublicIpAddress": "18.116.15.214",
                    "State": {
                        "Code": 16,
                        "Name": "running"
                    },
                    "StateTransitionReason": "",
                    "SubnetId": "subnet-0761518e281b46a6f",
                    "VpcId": "vpc-086e117465fe2d995",
                    "Architecture": "x86_64",
                    "BlockDeviceMappings": [
                        {
                            "DeviceName": "/dev/sda1",
                            "Ebs": {
                                "AttachTime": "2022-10-06T19:54:05+00:00",
                                "DeleteOnTermination": true,
                                "Status": "attached",
                                "VolumeId": "vol-05e4a71e526bddd83"
                            }
                        }
                    ],
                    "ClientToken": "4b977177-4ac9-4775-9945-23e2b6cc89d9",
                    "EbsOptimized": false,
                    "EnaSupport": true,
                    "Hypervisor": "xen",
                    "NetworkInterfaces": [
                        {
                            "Association": {
                                "IpOwnerId": "amazon",
                                "PublicDnsName": "",
                                "PublicIp": "18.116.15.214"
                            },
                            "Attachment": {
                                "AttachTime": "2022-10-06T19:54:04+00:00",
                                "AttachmentId": "eni-attach-05a1108df9cba083e",
                                "DeleteOnTermination": true,
                                "DeviceIndex": 0,
                                "Status": "attached",
                                "NetworkCardIndex": 0
                            },
                            "Description": "",
                            "Groups": [
                                {
                                    "GroupName": "DEMO-SG",
                                    "GroupId": "sg-02bf67daf0b0df37e"
                                }
                            ],
                            "Ipv6Addresses": [],
                            "MacAddress": "02:17:6d:93:61:64",
                            "NetworkInterfaceId": "eni-0ff61a8cde0757296",
                            "OwnerId": "<your_owner_id>",
                            "PrivateIpAddress": "10.0.0.165",
                            "PrivateIpAddresses": [
                                {
                                    "Association": {
                                        "IpOwnerId": "amazon",
                                        "PublicDnsName": "",
                                        "PublicIp": "18.116.15.214"
                                    },
                                    "Primary": true,
                                    "PrivateIpAddress": "10.0.0.165"
                                }
                            ],
                            "SourceDestCheck": true,
                            "Status": "in-use",
                            "SubnetId": "subnet-0761518e281b46a6f",
                            "VpcId": "vpc-086e117465fe2d995",
                            "InterfaceType": "interface"
                        }
                    ],
                    "RootDeviceName": "/dev/sda1",
                    "RootDeviceType": "ebs",
                    "SecurityGroups": [
                        {
                            "GroupName": "DEMO-SG",
                            "GroupId": "sg-02bf67daf0b0df37e"
                        }
                    ],
                    "SourceDestCheck": true,
                    "VirtualizationType": "hvm",
                    "CpuOptions": {
                        "CoreCount": 1,
                        "ThreadsPerCore": 1
                    },
                    "CapacityReservationSpecification": {
                        "CapacityReservationPreference": "open"
                    },
                    "HibernationOptions": {
                        "Configured": false
                    },
                    "MetadataOptions": {
                        "State": "applied",
                        "HttpTokens": "optional",
                        "HttpPutResponseHopLimit": 1,
                        "HttpEndpoint": "enabled",
                        "HttpProtocolIpv6": "disabled",
                        "InstanceMetadataTags": "disabled"
                    },
                    "EnclaveOptions": {
                        "Enabled": false
                    },
                    "PlatformDetails": "Linux/UNIX",
                    "UsageOperation": "RunInstances",
                    "UsageOperationUpdateTime": "2022-10-06T19:54:04+00:00",
                    "PrivateDnsNameOptions": {
                        "HostnameType": "ip-name",
                        "EnableResourceNameDnsARecord": false,
                        "EnableResourceNameDnsAAAARecord": false
                    },
                    "MaintenanceOptions": {
                        "AutoRecovery": "default"
                    }
                }
            ],
            "OwnerId": "<your_owner_id>",
            "ReservationId": "r-01fb8da8caa99b0b1"
        }
    ]
}
```
### Verifying the EC2 Instance 

- Retrieve ec2 instance public ip address
>aws ec2 describe-instances --instance-ids <InstanceId> --query=Reservations[].Instances[].PublicIpAddress
```json
aws ec2 describe-instances --instance-ids i-0252fb4f6c4e3ba17 --query=Reservations[].Instances[].PublicIpAddress
[
    "18.116.15.214"
]
```

### Verifying the EC2 Instance 
- Stop ec2 instance
>aws ec2 stop-instances --instance-ids <InstanceId>
```json
aws ec2 stop-instances --instance-ids i-0252fb4f6c4e3ba17
{
    "StoppingInstances": [
        {
            "CurrentState": {
                "Code": 64,
                "Name": "stopping"
            },
            "InstanceId": "i-0252fb4f6c4e3ba17",
            "PreviousState": {
                "Code": 16,
                "Name": "running"
            }
        }
    ]
}

aws ec2 describe-instances --instance-ids i-0252fb4f6c4e3ba17 --query=Reservations[].Instances[].State.Name
[
    "stopped"
]
```

- Start an existing ec2 instance
>aws ec2 start-instances --instance-ids <InstanceId>
```json
aws ec2 start-instances --instance-ids i-0252fb4f6c4e3ba17
{
    "StartingInstances": [
        {
            "CurrentState": {
                "Code": 0,
                "Name": "pending"
            },
            "InstanceId": "i-0252fb4f6c4e3ba17",
            "PreviousState": {
                "Code": 80,
                "Name": "stopped"
            }
        }
    ]
}

aws ec2 describe-instances --instance-ids i-0252fb4f6c4e3ba17 --query=Reservations[].Instances[].State.Name
[
    "running"
]
```

- get all ec2 instances by instanceId
>aws ec2 describe-instances
```json
aws ec2 describe-instances --query=Reservations[].Instances[].InstanceId
[
    "i-0252fb4f6c4e3ba17",
    "i-0c6ff7e7e2f68480d"
]
```