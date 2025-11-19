Phased approach to modernizing applications in the AWS Cloud

# AWS Prescriptive Guidance

Copyright © 2025 Amazon Web Services, Inc. and/or its affiliates. All rights reserved.


**AWS Prescriptive Guidance: Phased approach to modernizing**

**applications in the AWS Cloud**

Copyright © 2025 Amazon Web Services, Inc. and/or its affiliates. All rights reserved.

Amazon's trademarks and trade dress may not be used in connection with any product or service
that is not Amazon's, in any manner that is likely to cause confusion among customers, or in any
manner that disparages or discredits Amazon. All other trademarks not owned by Amazon are
the property of their respective owners, who may or may not be affiliated with, connected to, or
sponsored by Amazon.


## Table of Contents



## Phased approach to modernizing applications in the AWS

## Cloud

_Vijay Thumma and Ashish Ameta, Amazon Web Services (AWS)_

_May 2023_ (document history)

Modernization requires a multi-dimensional approach to adopt and consume new technology, to
deliver portfolio, application, and infrastructure value faster, and to position organizations for
scaling at an optimal price. It involves optimizing, maintaining applications, and operating in that
modernized model without disruption, and requires that you simplify your business operations,
architecture, and overall engineering practices.

Modernization is not just about applications; it requires a modern infrastructure that provides a
secure and flexible operations framework. Applications and infrastructure are inseparable when
it comes to business process quality, availability, and agility. Modernizing applications without
taking infrastructure into account leads to high overall costs and negatively impacts performance
and quality. Modern applications are built with a combination of new architecture patterns,
operational models, and software delivery processes. They scale up and down from zero to millions
of users, manage terabytes (if not petabytes) of data, are available globally, and respond in
milliseconds. When you modernize the portfolio of workloads you manage in the Amazon Web
Services (AWS) Cloud, you replatform, refactor, or replace these workloads by using containers,
serverless technologies, purpose-built data stores, and software automation, to gain the fullest
agility and total cost optimization (TCO) benefits offered by AWS.

This guide is for application owners, business owners, architects, technical leads, and project
managers. It discusses how to develop foundational capabilities for applications selected in the
modernization assessment phase, and ways to accelerate modernization efforts by using a phased
approach.

The guide is part of a content series that covers the application modernization approach
recommended by AWS. The series also includes:

- Strategy for modernizing applications in the AWS Cloud
- Evaluating modernization readiness for applications in the AWS Cloud
- Decomposing monoliths into microservices
- Integrating microservices by using AWS serverless services

```
1
```

- Enabling data persistence in microservices

### Targeted business outcomes......................................................................................................................

You should expect the following outcomes from the phased approach to application
modernization:

- Organizational capacity and capabilities to innovate faster, by using the build-and-prove
    approach and cloud-native architectures such as microservices.
- A change management and operational model that builds organizational readiness through
    training and tool improvements.
- A team approach, which helps deliver initial results in as little as 12 weeks, provides experiential
    learning, and enables independent, lasting customer success.
- A composable application architecture based on microservices, APIs, reusable components, and
    containerization.
- A scalable modernization roadmap for select strategic applications, which includes prescriptive
    guidance to work in a _split-and-seed_ model. In this model, modernization capabilities and
    services are scaled across multiple engineering teams that focus on business outcomes. As
    new minimum viable products (MVPs) are defined, initial team members split up to create new
    product teams.

Targeted business outcomes 2


## Modernization process....................................................................................................................

The goal of a phased approach to modernization is to provide incremental value by using
modernization dimensions, to apply these to a subset of core, business-differentiating applications,
and to accelerate modern technology adoption. The phased approach consists of three steps:

1.Evaluate the maturity of applications by using a modernization diagnostic playbook. Take a
comprehensive approach to adoption, and develop processes that are aligned to intended
business outcomes.

2.Start small and prepare to deliver an MVP to gain momentum by driving business results early
and incrementally. This phase typically takes 12 to 16 weeks.

3.Create a scalable modernization roadmap to work in a split-and-seed model.

The following sections discuss these steps in more detail.

**Topics**

- Step 1. Evaluate your applications
- Step 2. Start small and build momentum
- Step 3. Create a scalable modernization roadmap

### Step 1. Evaluate your applications...........................................................................................................

The goals of this phase are to:

- Thoroughly understand your application landscape and prepare your applications for modern
    data platforms, so you can accelerate the time to value without impacting your business, and
    then modernize, optimize, and scale.
- Profile your application landscape to identify the benefits, risks, and costs associated with
    change.
- Provide an end-to-end set of services: from strategy and planning; through deployment,
    migration, and application modernization; to ongoing support.
- Build policies, recommendations, and controls that provide reusable practices and tools to
    deliver ongoing business value.

Step 1. Evaluate your applications 3


In the evaluation phase, application owners and architects use a modernization diagnostic
playbook to validate their modernization goals and priorities.

#### Using the modernization diagnostic playbook.................................................................................

A modernization diagnostic playbook provides a process for determining the value of moving from
the current state to the future state for the enterprise. This is inclusive of technology changes that
modernization involves.

You use the diagnostic playbook to determine the priority of your application or application
suite for cloud modernization, and to identify the components that need to addressed during
modernization.

**Diagnostic dimensions**

The modernization diagnostics playbook helps you understand the following dimensions of the
current and target (post-migration) state of an application or a group of applications:

- Application grouping – Is there a reason to group applications (for example, by technology or
    operating model) for modernization?
- Sequencing – Is there an order in which applications should be modernized, based on
    dependencies?
- Technology – What are the technology categories (for example, middleware, database,
    messaging)?
- Dependencies – Do the applications have key dependencies on other systems or middleware?
- Environments – How many development, testing, and production environments are used?
- Storage – What are storage requirements (for example, the number of copies of the test data)?
- Operating model – Can all components of the application adopt a continuous integration and
    continuous delivery (CI/CD) pipeline?
    - If so, what infrastructure responsibilities should be distributed to application teams and to
       whom?
    - If not, what infrastructure responsibilities (for example, patching) should remain with a
       operations team?
- Delivery model:
    - Based on the application or group of applications, should you replatform, refactor, rewrite, or
       replace?

Using the modernization diagnostic playbook 4


- Which portion of the modernization should use cloud-native services?
- Skill sets – What expertise is required? For example:
- A cloud application background to build applications with a modular architecture by using
container and serverless technologies from the ground up.
- DevOps expertise to develop solutions in the areas of CI/CD processes, infrastructure as code,
and automation or application observability by using open-source and AWS tools and services.
- Modernization approach – Considering the current state of the applications, cloud technology
choices, current technical debt, CI/CD, monitoring, skills, and operating model, what is the
technical migration work that needs to be done?
- Modernization timing – What are the business portfolio timing considerations or other planned
work considerations that might affect modernization timing?
- Unit and total cost of infrastructure – What is the annual cost of maintaining your workload on
premises vs. on AWS, based on economic analysis?

Evaluating applications against these dimensions help you stay anchored in business, technology,
and economics as you drive your modernization to the cloud.

**Building blocks**

When you’re modernizing applications, you can classify your observations into three building
blocks: business agility, organizational agility, and engineering effectiveness.

- **Business agility** – Practices that concern the effectiveness within the business to translate
    business needs into requirements. How responsive the delivery organization is to business
    requests, and how much control the business has in releasing functionality into production
    environments.
- **Organizational agility** – Practices that define delivery processes. Examples include agile
    methodology and DevOps ceremonies as well as role assignment and clarity, and overall
    collaboration, communication, and enablement across the organization.
- **Engineering effectiveness** – Development practices related to quality assurance, testing, CI/CD,
    configuration management, application design, and source code management.

Using the modernization diagnostic playbook 5


#### Identifying metrics..................................................................................................................................

To learn if you are delivering what matters to your customers, you must implement measures that
drive improvement and accelerate delivery. Goal, question, metric (GQM) provides an effective
framework for ensuring that your measures meet these criteria. Use this framework to work back
from your goals by following these steps:

1.Identify the goal or outcome that you are undertaking.

2.Derive the questions that must be answered to determine whether the goal is being met.

3.Decide what should or could be measured to answer the questions adequately. There are two
categories of measures:

- Product metrics, which ensure that you are delivering what matters to your customers.
- Operational metrics, which ensure that you are improving your software delivery lifecycle.

**Product metrics**

Product metrics focus on business outcomes and should be established when the return on
investment (ROI) for a new scope of work is determined. A useful technique for establishing
a product metric is to ask what will change in the business when that new scope of work is
implemented. It’s helpful to formalize this thinking into the form of a test that focuses on what
would be true when a modernization feature is delivered.

For example, if you believe that migrating transactions out of legacy systems will unlock new
opportunities to onboard clients, what is the improvement? How much capacity has to be created
to onboard the next client? How would a test be constructed to validate that outcome? For this
scenario, your product metrics might include the following:

- Identify the business value test or hypothesis (for example, freeing _x_ percent of transaction
    capacity will onboard _y_ percent of new business).
- Establish the baseline (for example, the current capacity of _x_ transactions supports _y_ customers).
- Validate the outcome (for example, you have improved capacity by _x_ percent, so can you now
    onboard _y_ percent new business?)

Identifying metrics 6


**Operational metrics**

To determine whether you are improving your software delivery lifecycle and accelerating your
modernization, you must know your lead time and implementation time for delivering software.
That is, how quickly can you convert a business need into functionality in production?

Useful operational metrics include:

- Lead time – How much time does it take for a scope of work to go from request to production?
- Cycle time – How long does it take to implement a scope of work, from start to finish?
- Deployment frequency – How often do you deploy changes to production?
- Time to restore service – How long does it take to recover from failure (measured as the mean
    time to repair or MTTR)?
- Change failure rate – What is the mean time between failures (MTBF)?

### Step 2. Start small and build momentum..............................................................................................

The goal of this step is to deliver an initial minimal viable product (MVP) to gain momentum. This
approach enables you to drive business results early and incrementally.

#### Validating priority drivers......................................................................................................................

Before you start the modernization work with application teams, we recommend that you validate
the priority drivers that you determined earlier. Follow these steps:

1.Compile the information you need from the diagnostic playbook.

- Gather the priority drivers and feasibility assessment from the priority applications list.
- Gather the transition and goal state dispositions for your applications.
- Identify the application owners, architects, and stakeholders in cloud modernization planning.
- Solicit information on dependencies or application suite sequencing, if known.
- Determine how inventory entries relate to dependencies or application suite groupings.
    Applications might have individual components that are tightly coupled with, or dependent
    on, other components, and you might want to modernize these components together.

2.Schedule a one-hour or two-hour meeting with the people from step 1 to validate priority
drivers.

Step 2. Start small and build momentum 7


- Try to group multiple (up to three or four) applications by solution engineer or architect,
    and discuss them in one meeting, based on application dependency or application suite
    information.
- Determine the roles and expectations for each team member for this upcoming meeting.

3.Conduct the meeting.

#### Finalizing details......................................................................................................................................

After you follow the process in the previous section to validate the priority drivers, you can gather
the details to determine the modernization approach and timing.

In this phase, the core team works side by side with application teams in short, two-day sprints to
design a future state for their applications on the AWS Cloud. Activities include product definition,
product discovery, story writing, value stream mapping, and designing CI/CD processes. Here are
some ideas:

- Model each individual component of the application (for example, network configurations,
    storage configurations, databases, servers, and how the application is deployed on the servers).
- Deconstruct that model into its different building blocks and configurations by using tools such
    as containers or serverless technologies.
- Separate application functionality from any dependencies on underlying infrastructure. Abstract
    the functions of an application into components that you can move without changing any source
    code.
- Tightly integrate with DevOps by using CI/CD tools and mechanisms.

#### Building foundational platform services and modernizing applications.....................................

In this 12-week phase, the core team is supported by full-stack teams to deliver the prioritized
business use case. This work is carried out by multiple two-pizza teams. For example, a platform
engineering team is formed to develop foundational platform services, and a product team is
formed to deliver new business outcomes:

- The platform engineering team configures, integrates, and customizes the AWS services that
    support the cloud foundation, developer workflow, and data analytics capabilities. Larger and
    more complex enterprises might have multiple teams supporting each of these capabilities.

Finalizing details 8


- The product team develops new services and experiences for the business outcomes prioritized
    in the inception phase. As the product team develops new services, they also modernize core
    business capabilities.

The platform engineering and product teams deliver a minimal viable product (MVP) that you can
evaluate. Upon the success of the initial MVP, you can scale your modernization program by using
a split-and-seed approach, whereby new applications are identified and initial team members are
split up to create new product teams.

### Step 3. Create a scalable modernization roadmap...............................................................................

After the initial MVP release of the prioritized outcomes and applications, we recommend that you
develop a roadmap for scaling and accelerating your modernization efforts, improving developer
productivity, and innovating rapidly. The core team splits and seeds new teams in order to scale
your organization’s capabilities and services across multiple engineering teams that are focused
on business outcomes. By employing the split-and-seed approach over time, your organization can
take on more development and accelerate the velocity of modernization.

The modernization roadmap should outline a pragmatic and continuous approach to application
modernization with clearly defined patterns such as event-driven, strangler, domain-driven
designs, decomposition, modern database options, and so on.

The roadmap should include a decision tree matrix, as shown in the following diagram, to identify
a component of an application and move it to a managed service (such as a database service) with
no changes to business logic, or to make code-level changes to improve performance, scalability,
manageability, reliability, and resource usage.

Step 3. Create a scalable modernization roadmap 9


- Introduction.....................................................................................................................................
   - Targeted business outcomes......................................................................................................................
- Modernization process....................................................................................................................
   - Step 1. Evaluate your applications...........................................................................................................
      - Using the modernization diagnostic playbook.................................................................................
      - Identifying metrics..................................................................................................................................
   - Step 2. Start small and build momentum..............................................................................................
      - Validating priority drivers......................................................................................................................
      - Finalizing details......................................................................................................................................
      - Building foundational platform services and modernizing applications.....................................
   - Step 3. Create a scalable modernization roadmap...............................................................................
- Modernization readiness factors..................................................................................................
   - Code..............................................................................................................................................................
   - Build and test.............................................................................................................................................
   - Release..........................................................................................................................................................
   - Operate.........................................................................................................................................................
   - Optimize.......................................................................................................................................................
   - Readiness......................................................................................................................................................
- Next steps......................................................................................................................................
- Resources........................................................................................................................................
   - Related guides............................................................................................................................................
   - AWS resources.............................................................................................................................................
- Document history..........................................................................................................................
- Glossary..........................................................................................................................................
   - #.....................................................................................................................................................................
   - A.....................................................................................................................................................................
   - B.....................................................................................................................................................................
   - C.....................................................................................................................................................................
   - D.....................................................................................................................................................................
   - E.....................................................................................................................................................................
   - F.....................................................................................................................................................................
   - G.....................................................................................................................................................................
   - H.....................................................................................................................................................................
   - I......................................................................................................................................................................
- L.....................................................................................................................................................................
- M....................................................................................................................................................................
- O....................................................................................................................................................................
- P.....................................................................................................................................................................
- Q....................................................................................................................................................................
- R.....................................................................................................................................................................
- S.....................................................................................................................................................................
- T.....................................................................................................................................................................
- U.....................................................................................................................................................................
- V.....................................................................................................................................................................
- W....................................................................................................................................................................
- Z.....................................................................................................................................................................
- Step 3. Create a scalable modernization roadmap


## Modernization readiness factors..................................................................................................

Observe the following standards and best practices when you’re modernizing your applications.

**Topics**

- Code
- Build and test
- Release
- Operate
- Optimize
- Readiness

### Code..............................................................................................................................................................

- Provide code comments that document the functionality of your software, and use them to
    generate documentation.
- Follow code management and deployment processes that support frequent code check-ins and
    traceability to feature requests.
- Build test suites that include unit, functional, performance, and critical path tests, with 100
    percent code coverage.
- Encourage code reuse to deliver the same or similar functionality in your code base.
- Develop prototypes to validate features with users before investing in full code development.

### Build and test.............................................................................................................................................

- Redefine feature completeness based on testing, to improve quality and prevent recurring issues.
- Automate acceptance tests.
- Monitor all automated tests, and establish a process for handling failures in place.
- Track performance in both production and non-production environments, define service-level
    objectives (SLOs) based on realistic traffic and load testing, and provide the ability to scale to
    meet performance requirements.

Code 11


- Abstract sensitive data from configuration files, and provide tools that automate and monitor
    configurations.

### Release..........................................................................................................................................................

- Automate deployments with support for dependencies (for example, database releases),
    regression testing, and tracking.
- Release code to the production environment incrementally, after every successful build.
- Manage feature flags (toggles) effectively: support run-time configuration, monitor usage,
    maintain flags throughout the development cycle, and assign owners by category.
- Provide traceability in your build pipelines, to track triggers, failure notifications, and successful
    completion.
- Run automated deployment processes and tests for “zero touch” code updates in continuous
    delivery.
- Use zero-downtime, fully automated blue/green deployment methodologies.
- Make sure that your database schema changes are implemented consistently across all
    development and production environments.

### Operate.........................................................................................................................................................

- Create a DevOps triage runbook that’s integrated with your notification system.
- Make sure that your monitoring and notification system meets service-level objectives (SLOs)
    and supports thresholds, health checks, non-standard HTTP responses, and unexpected results.
- Establish effective risk management and disaster recovery processes.
- Develop a log rotation and retention strategy that meets your business and legal requirements.
- Develop dashboards that track product performance, measure the success of new features, and
    display alerts when metrics don’t meet expectations.

### Optimize.......................................................................................................................................................

- Review and improve processes regularly, based on performance and quality measures.
- Implement root cause analysis and prevention processes to prevent issues from recurring.

Release 12


- Provide data-driven metrics that capture product health, and make sure that all notifications and
    actions are based on these metrics.

### Readiness......................................................................................................................................................

- Dedicate a cross-functional team (including business partners, developers, testers, and
    architects) to your modernization efforts.

Readiness 13


## Next steps......................................................................................................................................

This guide provided a phased and incremental approach to modernizing your applications. We
recommend that you begin scoping your workstreams with technology and delivery for the short,
medium, and long term. You can expect to invest more in tools, frameworks, and practices to drive
more effective delivery and engineering practices across teams. Set goals for the modernization
process, understand each application you’re planning to modernize, and choose the optimal
modernization approach for each application. Monitor and optimize your progress.

AWS will engage with your organization’s business development teams to drive technology
modernization and to manage your end-to-end needs, including application architecture, design,
and development; mobile enablement; testing; and collaborative solutions. These services combine
proven processes, intelligent automation, use of data and patterns, open standards, and the right
people to help you modernize your legacy applications. Primary goals are targeted to:

- Assist to develop a platform that offers a fully automated, tools-based approach for modernizing
    legacy technology, and couple it with holistic knowledge of modernization.
- Build an MVP with full stack teams, with modernization engineering capabilities focused on
    customer outcomes and scale.

AWS Professional Services and AWS Partners work directly with senior technology and business
customer stakeholders to drive enterprise modernization, while iteratively delivering end-customer
value.

```
14
```

## Resources........................................................................................................................................

### Related guides............................................................................................................................................

- Strategy for modernizing applications in the AWS Cloud
- Evaluating modernization readiness for applications in the AWS Cloud
- Modernizing operations in the AWS Cloud
- Decomposing monoliths into microservices
- Integrating microservices by using AWS serverless services
- Enabling data persistence in microservices
- AWS Change Acceleration 6-Point Framework and Organizational Change Management Toolkit

### AWS resources.............................................................................................................................................

- AWS documentation
- AWS general reference
- AWS glossary

Related guides 15


## Document history..........................................................................................................................

The following table describes significant changes to this guide. If you want to be notified about
future updates, you can subscribe to an RSS feed.

```
Change Description Date
```
```
Expanded guidance — May 25, 2023
```
```
Initial publication — December 18, 2020
```
```
16
```

## AWS Prescriptive Guidance glossary

The following are commonly used terms in strategies, guides, and patterns provided by AWS
Prescriptive Guidance. To suggest entries, please use the **Provide feedback** link at the end of the

## Glossary..........................................................................................................................................

### Numbers

7 Rs

```
Seven common migration strategies for moving applications to the cloud. These strategies build
upon the 5 Rs that Gartner identified in 2011 and consist of the following:
```
- Refactor/re-architect – Move an application and modify its architecture by taking full
    advantage of cloud-native features to improve agility, performance, and scalability. This
    typically involves porting the operating system and database. Example: Migrate your on-
    premises Oracle database to the Amazon Aurora PostgreSQL-Compatible Edition.
- Replatform (lift and reshape) – Move an application to the cloud, and introduce some level
    of optimization to take advantage of cloud capabilities. Example: Migrate your on-premises
    Oracle database to Amazon Relational Database Service (Amazon RDS) for Oracle in the AWS
    Cloud.
- Repurchase (drop and shop) – Switch to a different product, typically by moving from
    a traditional license to a SaaS model. Example: Migrate your customer relationship
    management (CRM) system to Salesforce.com.
- Rehost (lift and shift) – Move an application to the cloud without making any changes to
    take advantage of cloud capabilities. Example: Migrate your on-premises Oracle database to
    Oracle on an EC2 instance in the AWS Cloud.
- Relocate (hypervisor-level lift and shift) – Move infrastructure to the cloud without
    purchasing new hardware, rewriting applications, or modifying your existing operations.
    You migrate servers from an on-premises platform to a cloud service for the same platform.
    Example: Migrate a Microsoft Hyper-V application to AWS.
- Retain (revisit) – Keep applications in your source environment. These might include
    applications that require major refactoring, and you want to postpone that work until a later
    time, and legacy applications that you want to retain, because there’s no business justification
    for migrating them.

# 17


- Retire – Decommission or remove applications that are no longer needed in your source
    environment.

### A.....................................................................................................................................................................

##### ABAC

```
See attribute-based access control.
```
abstracted services

```
See managed services.
```
ACID

```
See atomicity, consistency, isolation, durability.
```
active-active migration

```
A database migration method in which the source and target databases are kept in sync (by
using a bidirectional replication tool or dual write operations), and both databases handle
transactions from connecting applications during migration. This method supports migration in
small, controlled batches instead of requiring a one-time cutover. It’s more flexible but requires
more work than active-passive migration.
```
active-passive migration

```
A database migration method in which the source and target databases are kept in sync, but
only the source database handles transactions from connecting applications while data is
replicated to the target database. The target database doesn’t accept any transactions during
migration.
```
aggregate function

```
A SQL function that operates on a group of rows and calculates a single return value for the
group. Examples of aggregate functions include SUM and MAX.
```
AI

```
See artificial intelligence.
```
AIOps

```
See artificial intelligence operations.
```
A 18


anonymization

```
The process of permanently deleting personal information in a dataset. Anonymization can help
protect personal privacy. Anonymized data is no longer considered to be personal data.
```
anti-pattern

```
A frequently used solution for a recurring issue where the solution is counter-productive,
ineffective, or less effective than an alternative.
```
application control

```
A security approach that allows the use of only approved applications in order to help protect a
system from malware.
```
application portfolio

```
A collection of detailed information about each application used by an organization, including
the cost to build and maintain the application, and its business value. This information is key to
the portfolio discovery and analysis process and helps identify and prioritize the applications to
be migrated, modernized, and optimized.
```
artificial intelligence (AI)

```
The field of computer science that is dedicated to using computing technologies to perform
cognitive functions that are typically associated with humans, such as learning, solving
problems, and recognizing patterns. For more information, see What is Artificial Intelligence?
```
artificial intelligence operations (AIOps)

```
The process of using machine learning techniques to solve operational problems, reduce
operational incidents and human intervention, and increase service quality. For more
information about how AIOps is used in the AWS migration strategy, see the operations
integration guide.
```
asymmetric encryption

```
An encryption algorithm that uses a pair of keys, a public key for encryption and a private key
for decryption. You can share the public key because it isn’t used for decryption, but access to
the private key should be highly restricted.
```
atomicity, consistency, isolation, durability (ACID)

```
A set of software properties that guarantee the data validity and operational reliability of a
database, even in the case of errors, power failures, or other problems.
```
A 19


attribute-based access control (ABAC)

```
The practice of creating fine-grained permissions based on user attributes, such as department,
job role, and team name. For more information, see ABAC for AWS in the AWS Identity and
Access Management (IAM) documentation.
```
authoritative data source

```
A location where you store the primary version of data, which is considered to be the most
reliable source of information. You can copy data from the authoritative data source to other
locations for the purposes of processing or modifying the data, such as anonymizing, redacting,
or pseudonymizing it.
```
Availability Zone

```
A distinct location within an AWS Region that is insulated from failures in other Availability
Zones and provides inexpensive, low-latency network connectivity to other Availability Zones in
the same Region.
```
AWS Cloud Adoption Framework (AWS CAF)

```
A framework of guidelines and best practices from AWS to help organizations develop an
efficient and effective plan to move successfully to the cloud. AWS CAF organizes guidance
into six focus areas called perspectives: business, people, governance, platform, security,
and operations. The business, people, and governance perspectives focus on business skills
and processes; the platform, security, and operations perspectives focus on technical skills
and processes. For example, the people perspective targets stakeholders who handle human
resources (HR), staffing functions, and people management. For this perspective, AWS CAF
provides guidance for people development, training, and communications to help ready the
organization for successful cloud adoption. For more information, see the AWS CAF website and
the AWS CAF whitepaper.
```
AWS Workload Qualification Framework (AWS WQF)

```
A tool that evaluates database migration workloads, recommends migration strategies, and
provides work estimates. AWS WQF is included with AWS Schema Conversion Tool (AWS SCT). It
analyzes database schemas and code objects, application code, dependencies, and performance
characteristics, and provides assessment reports.
```
A 20


### B.....................................................................................................................................................................

bad bot

```
A bot that is intended to disrupt or cause harm to individuals or organizations.
```
BCP

```
See business continuity planning.
```
behavior graph

```
A unified, interactive view of resource behavior and interactions over time. You can use a
behavior graph with Amazon Detective to examine failed logon attempts, suspicious API
calls, and similar actions. For more information, see Data in a behavior graph in the Detective
documentation.
```
big-endian system

```
A system that stores the most significant byte first. See also endianness.
```
binary classification

```
A process that predicts a binary outcome (one of two possible classes). For example, your ML
model might need to predict problems such as “Is this email spam or not spam?" or "Is this
product a book or a car?"
```
bloom filter

```
A probabilistic, memory-efficient data structure that is used to test whether an element is a
member of a set.
```
blue/green deployment

```
A deployment strategy where you create two separate but identical environments. You run the
current application version in one environment (blue) and the new application version in the
other environment (green). This strategy helps you quickly roll back with minimal impact.
```
bot

```
A software application that runs automated tasks over the internet and simulates human
activity or interaction. Some bots are useful or beneficial, such as web crawlers that index
information on the internet. Some other bots, known as bad bots , are intended to disrupt or
cause harm to individuals or organizations.
```
B 21


botnet

```
Networks of bots that are infected by malware and are under the control of a single party,
known as a bot herder or bot operator. Botnets are the best-known mechanism to scale bots and
their impact.
```
branch

```
A contained area of a code repository. The first branch created in a repository is the main
branch. You can create a new branch from an existing branch, and you can then develop
features or fix bugs in the new branch. A branch you create to build a feature is commonly
referred to as a feature branch. When the feature is ready for release, you merge the feature
branch back into the main branch. For more information, see About branches (GitHub
documentation).
```
break-glass access

```
In exceptional circumstances and through an approved process, a quick means for a user to
gain access to an AWS account that they don't typically have permissions to access. For more
information, see the Implement break-glass procedures indicator in the AWS Well-Architected
guidance.
```
brownfield strategy

```
The existing infrastructure in your environment. When adopting a brownfield strategy for a
system architecture, you design the architecture around the constraints of the current systems
and infrastructure. If you are expanding the existing infrastructure, you might blend brownfield
and greenfield strategies.
```
buffer cache

```
The memory area where the most frequently accessed data is stored.
```
business capability

```
What a business does to generate value (for example, sales, customer service, or marketing).
Microservices architectures and development decisions can be driven by business capabilities.
For more information, see the Organized around business capabilities section of the Running
containerized microservices on AWS whitepaper.
```
business continuity planning (BCP)

```
A plan that addresses the potential impact of a disruptive event, such as a large-scale migration,
on operations and enables a business to resume operations quickly.
```
B 22


### C.....................................................................................................................................................................

##### CAF

```
See AWS Cloud Adoption Framework.
```
canary deployment

```
The slow and incremental release of a version to end users. When you are confident, you deploy
the new version and replace the current version in its entirety.
```
CCoE

```
See Cloud Center of Excellence.
```
CDC

```
See change data capture.
```
change data capture (CDC)

```
The process of tracking changes to a data source, such as a database table, and recording
metadata about the change. You can use CDC for various purposes, such as auditing or
replicating changes in a target system to maintain synchronization.
```
chaos engineering

```
Intentionally introducing failures or disruptive events to test a system’s resilience. You can use
AWS Fault Injection Service (AWS FIS) to perform experiments that stress your AWS workloads
and evaluate their response.
```
CI/CD

```
See continuous integration and continuous delivery.
```
classification

```
A categorization process that helps generate predictions. ML models for classification problems
predict a discrete value. Discrete values are always distinct from one another. For example, a
model might need to evaluate whether or not there is a car in an image.
```
client-side encryption

```
Encryption of data locally, before the target AWS service receives it.
```
C 23


Cloud Center of Excellence (CCoE)

```
A multi-disciplinary team that drives cloud adoption efforts across an organization, including
developing cloud best practices, mobilizing resources, establishing migration timelines, and
leading the organization through large-scale transformations. For more information, see the
CCoE posts on the AWS Cloud Enterprise Strategy Blog.
```
cloud computing

```
The cloud technology that is typically used for remote data storage and IoT device
management. Cloud computing is commonly connected to edge computing technology.
```
cloud operating model

```
In an IT organization, the operating model that is used to build, mature, and optimize one or
more cloud environments. For more information, see Building your Cloud Operating Model.
```
cloud stages of adoption

```
The four phases that organizations typically go through when they migrate to the AWS Cloud:
```
- Project – Running a few cloud-related projects for proof of concept and learning purposes
- Foundation – Making foundational investments to scale your cloud adoption (e.g., creating a
    landing zone, defining a CCoE, establishing an operations model)
- Migration – Migrating individual applications
- Re-invention – Optimizing products and services, and innovating in the cloud

```
These stages were defined by Stephen Orban in the blog post The Journey Toward Cloud-First
& the Stages of Adoption on the AWS Cloud Enterprise Strategy blog. For information about
how they relate to the AWS migration strategy, see the migration readiness guide.
```
CMDB

```
See configuration management database.
```
code repository

```
A location where source code and other assets, such as documentation, samples, and scripts,
are stored and updated through version control processes. Common cloud repositories include
GitHub or Bitbucket Cloud. Each version of the code is called a branch. In a microservice
structure, each repository is devoted to a single piece of functionality. A single CI/CD pipeline
can use multiple repositories.
```
C 24


cold cache

```
A buffer cache that is empty, not well populated, or contains stale or irrelevant data. This
affects performance because the database instance must read from the main memory or disk,
which is slower than reading from the buffer cache.
```
cold data

```
Data that is rarely accessed and is typically historical. When querying this kind of data, slow
queries are typically acceptable. Moving this data to lower-performing and less expensive
storage tiers or classes can reduce costs.
```
computer vision (CV)

```
A field of AI that uses machine learning to analyze and extract information from visual
formats such as digital images and videos. For example, Amazon SageMaker AI provides image
processing algorithms for CV.
```
configuration drift

```
For a workload, a configuration change from the expected state. It might cause the workload to
become noncompliant, and it's typically gradual and unintentional.
```
configuration management database (CMDB)

```
A repository that stores and manages information about a database and its IT environment,
including both hardware and software components and their configurations. You typically use
data from a CMDB in the portfolio discovery and analysis stage of migration.
```
conformance pack

```
A collection of AWS Config rules and remediation actions that you can assemble to customize
your compliance and security checks. You can deploy a conformance pack as a single entity in
an AWS account and Region, or across an organization, by using a YAML template. For more
information, see Conformance packs in the AWS Config documentation.
```
continuous integration and continuous delivery (CI/CD)

```
The process of automating the source, build, test, staging, and production stages of the
software release process. CI/CD is commonly described as a pipeline. CI/CD can help you
automate processes, improve productivity, improve code quality, and deliver faster. For more
information, see Benefits of continuous delivery. CD can also stand for continuous deployment.
For more information, see Continuous Delivery vs. Continuous Deployment.
```
C 25


##### CV

```
See computer vision.
```
### D.....................................................................................................................................................................

data at rest

```
Data that is stationary in your network, such as data that is in storage.
```
data classification

```
A process for identifying and categorizing the data in your network based on its criticality and
sensitivity. It is a critical component of any cybersecurity risk management strategy because
it helps you determine the appropriate protection and retention controls for the data. Data
classification is a component of the security pillar in the AWS Well-Architected Framework. For
more information, see Data classification.
```
data drift

```
A meaningful variation between the production data and the data that was used to train an ML
model, or a meaningful change in the input data over time. Data drift can reduce the overall
quality, accuracy, and fairness in ML model predictions.
```
data in transit

```
Data that is actively moving through your network, such as between network resources.
```
data mesh

```
An architectural framework that provides distributed, decentralized data ownership with
centralized management and governance.
```
data minimization

```
The principle of collecting and processing only the data that is strictly necessary. Practicing
data minimization in the AWS Cloud can reduce privacy risks, costs, and your analytics carbon
footprint.
```
data perimeter

```
A set of preventive guardrails in your AWS environment that help make sure that only trusted
identities are accessing trusted resources from expected networks. For more information, see
Building a data perimeter on AWS.
```
D 26


data preprocessing

```
To transform raw data into a format that is easily parsed by your ML model. Preprocessing data
can mean removing certain columns or rows and addressing missing, inconsistent, or duplicate
values.
```
data provenance

```
The process of tracking the origin and history of data throughout its lifecycle, such as how the
data was generated, transmitted, and stored.
```
data subject

```
An individual whose data is being collected and processed.
```
data warehouse

```
A data management system that supports business intelligence, such as analytics. Data
warehouses commonly contain large amounts of historical data, and they are typically used for
queries and analysis.
```
database definition language (DDL)

```
Statements or commands for creating or modifying the structure of tables and objects in a
database.
```
database manipulation language (DML)

```
Statements or commands for modifying (inserting, updating, and deleting) information in a
database.
```
DDL

```
See database definition language.
```
deep ensemble

```
To combine multiple deep learning models for prediction. You can use deep ensembles to
obtain a more accurate prediction or for estimating uncertainty in predictions.
```
deep learning

```
An ML subfield that uses multiple layers of artificial neural networks to identify mapping
between input data and target variables of interest.
```
D 27


defense-in-depth

```
An information security approach in which a series of security mechanisms and controls are
thoughtfully layered throughout a computer network to protect the confidentiality, integrity,
and availability of the network and the data within. When you adopt this strategy on AWS,
you add multiple controls at different layers of the AWS Organizations structure to help
secure resources. For example, a defense-in-depth approach might combine multi-factor
authentication, network segmentation, and encryption.
```
delegated administrator

```
In AWS Organizations, a compatible service can register an AWS member account to administer
the organization’s accounts and manage permissions for that service. This account is called the
delegated administrator for that service. For more information and a list of compatible services,
see Services that work with AWS Organizations in the AWS Organizations documentation.
```
deployment

```
The process of making an application, new features, or code fixes available in the target
environment. Deployment involves implementing changes in a code base and then building and
running that code base in the application’s environments.
```
development environment

```
See environment.
```
detective control

```
A security control that is designed to detect, log, and alert after an event has occurred.
These controls are a second line of defense, alerting you to security events that bypassed the
preventative controls in place. For more information, see Detective controls in Implementing
security controls on AWS.
```
development value stream mapping (DVSM)

```
A process used to identify and prioritize constraints that adversely affect speed and quality in
a software development lifecycle. DVSM extends the value stream mapping process originally
designed for lean manufacturing practices. It focuses on the steps and teams required to create
and move value through the software development process.
```
digital twin

```
A virtual representation of a real-world system, such as a building, factory, industrial
equipment, or production line. Digital twins support predictive maintenance, remote
monitoring, and production optimization.
```
D 28


dimension table

```
In a star schema, a smaller table that contains data attributes about quantitative data in a
fact table. Dimension table attributes are typically text fields or discrete numbers that behave
like text. These attributes are commonly used for query constraining, filtering, and result set
labeling.
```
disaster

```
An event that prevents a workload or system from fulfilling its business objectives in its primary
deployed location. These events can be natural disasters, technical failures, or the result of
human actions, such as unintentional misconfiguration or a malware attack.
```
disaster recovery (DR)

```
The strategy and process you use to minimize downtime and data loss caused by a disaster. For
more information, see Disaster Recovery of Workloads on AWS: Recovery in the Cloud in the
AWS Well-Architected Framework.
```
DML

```
See database manipulation language.
```
domain-driven design

```
An approach to developing a complex software system by connecting its components to
evolving domains, or core business goals, that each component serves. This concept was
introduced by Eric Evans in his book, Domain-Driven Design: Tackling Complexity in the Heart of
Software (Boston: Addison-Wesley Professional, 2003). For information about how you can use
domain-driven design with the strangler fig pattern, see Modernizing legacy Microsoft ASP.NET
(ASMX) web services incrementally by using containers and Amazon API Gateway.
```
DR

```
See disaster recovery.
```
drift detection

```
Tracking deviations from a baselined configuration. For example, you can use AWS
CloudFormation to detect drift in system resources, or you can use AWS Control Tower to detect
changes in your landing zone that might affect compliance with governance requirements.
```
DVSM

```
See development value stream mapping.
```
D 29


### E.....................................................................................................................................................................

##### EDA

```
See exploratory data analysis.
```
EDI

```
See electronic data interchange.
```
edge computing

```
The technology that increases the computing power for smart devices at the edges of an IoT
network. When compared with cloud computing, edge computing can reduce communication
latency and improve response time.
```
electronic data interchange (EDI)

```
The automated exchange of business documents between organizations. For more information,
see What is Electronic Data Interchange.
```
encryption

```
A computing process that transforms plaintext data, which is human-readable, into ciphertext.
```
encryption key

```
A cryptographic string of randomized bits that is generated by an encryption algorithm. Keys
can vary in length, and each key is designed to be unpredictable and unique.
```
endianness

```
The order in which bytes are stored in computer memory. Big-endian systems store the most
significant byte first. Little-endian systems store the least significant byte first.
```
endpoint

```
See service endpoint.
```
endpoint service

```
A service that you can host in a virtual private cloud (VPC) to share with other users. You can
create an endpoint service with AWS PrivateLink and grant permissions to other AWS accounts
or to AWS Identity and Access Management (IAM) principals. These accounts or principals
can connect to your endpoint service privately by creating interface VPC endpoints. For more
```
E 30


```
information, see Create an endpoint service in the Amazon Virtual Private Cloud (Amazon VPC)
documentation.
```
enterprise resource planning (ERP)

```
A system that automates and manages key business processes (such as accounting, MES, and
project management) for an enterprise.
```
envelope encryption

```
The process of encrypting an encryption key with another encryption key. For more
information, see Envelope encryption in the AWS Key Management Service (AWS KMS)
documentation.
```
environment

```
An instance of a running application. The following are common types of environments in cloud
computing:
```
- development environment – An instance of a running application that is available only to the
    core team responsible for maintaining the application. Development environments are used
    to test changes before promoting them to upper environments. This type of environment is
    sometimes referred to as a _test environment_.
- lower environments – All development environments for an application, such as those used
    for initial builds and tests.
- production environment – An instance of a running application that end users can access. In a
    CI/CD pipeline, the production environment is the last deployment environment.
- upper environments – All environments that can be accessed by users other than the core
    development team. This can include a production environment, preproduction environments,
    and environments for user acceptance testing.

epic

```
In agile methodologies, functional categories that help organize and prioritize your work. Epics
provide a high-level description of requirements and implementation tasks. For example, AWS
CAF security epics include identity and access management, detective controls, infrastructure
security, data protection, and incident response. For more information about epics in the AWS
migration strategy, see the program implementation guide.
```
ERP

```
See enterprise resource planning.
```
E 31


exploratory data analysis (EDA)

```
The process of analyzing a dataset to understand its main characteristics. You collect or
aggregate data and then perform initial investigations to find patterns, detect anomalies,
and check assumptions. EDA is performed by calculating summary statistics and creating data
visualizations.
```
### F.....................................................................................................................................................................

fact table

```
The central table in a star schema. It stores quantitative data about business operations.
Typically, a fact table contains two types of columns: those that contain measures and those
that contain a foreign key to a dimension table.
```
fail fast

```
A philosophy that uses frequent and incremental testing to reduce the development lifecycle. It
is a critical part of an agile approach.
```
fault isolation boundary

```
In the AWS Cloud, a boundary such as an Availability Zone, AWS Region, control plane, or data
plane that limits the effect of a failure and helps improve the resilience of workloads. For more
information, see AWS Fault Isolation Boundaries.
```
feature branch

```
See branch.
```
features

```
The input data that you use to make a prediction. For example, in a manufacturing context,
features could be images that are periodically captured from the manufacturing line.
```
feature importance

```
How significant a feature is for a model’s predictions. This is usually expressed as a numerical
score that can be calculated through various techniques, such as Shapley Additive Explanations
(SHAP) and integrated gradients. For more information, see Machine learning model
interpretability with AWS.
```
F 32


feature transformation

```
To optimize data for the ML process, including enriching data with additional sources, scaling
values, or extracting multiple sets of information from a single data field. This enables the ML
model to benefit from the data. For example, if you break down the “2021-05-27 00:15:37”
date into “2021”, “May”, “Thu”, and “15”, you can help the learning algorithm learn nuanced
patterns associated with different data components.
```
few-shot prompting

```
Providing an LLM with a small number of examples that demonstrate the task and desired
output before asking it to perform a similar task. This technique is an application of in-context
learning, where models learn from examples ( shots ) that are embedded in prompts. Few-shot
prompting can be effective for tasks that require specific formatting, reasoning, or domain
knowledge. See also zero-shot prompting.
```
FGAC

```
See fine-grained access control.
```
fine-grained access control (FGAC)

```
The use of multiple conditions to allow or deny an access request.
```
flash-cut migration

```
A database migration method that uses continuous data replication through change data
capture to migrate data in the shortest time possible, instead of using a phased approach. The
objective is to keep downtime to a minimum.
```
FM

```
See foundation model.
```
foundation model (FM)

```
A large deep-learning neural network that has been training on massive datasets of generalized
and unlabeled data. FMs are capable of performing a wide variety of general tasks, such as
understanding language, generating text and images, and conversing in natural language. For
more information, see What are Foundation Models.
```
F 33


### G.....................................................................................................................................................................

generative AI

```
A subset of AI models that have been trained on large amounts of data and that can use a
simple text prompt to create new content and artifacts, such as images, videos, text, and audio.
For more information, see What is Generative AI.
```
geo blocking

```
See geographic restrictions.
```
geographic restrictions (geo blocking)

```
In Amazon CloudFront, an option to prevent users in specific countries from accessing content
distributions. You can use an allow list or block list to specify approved and banned countries.
For more information, see Restricting the geographic distribution of your content in the
CloudFront documentation.
```
Gitflow workflow

```
An approach in which lower and upper environments use different branches in a source code
repository. The Gitflow workflow is considered legacy, and the trunk-based workflow is the
modern, preferred approach.
```
golden image

```
A snapshot of a system or software that is used as a template to deploy new instances of that
system or software. For example, in manufacturing, a golden image can be used to provision
software on multiple devices and helps improve speed, scalability, and productivity in device
manufacturing operations.
```
greenfield strategy

```
The absence of existing infrastructure in a new environment. When adopting a greenfield
strategy for a system architecture, you can select all new technologies without the restriction
of compatibility with existing infrastructure, also known as brownfield. If you are expanding the
existing infrastructure, you might blend brownfield and greenfield strategies.
```
guardrail

```
A high-level rule that helps govern resources, policies, and compliance across organizational
units (OUs). Preventive guardrails enforce policies to ensure alignment to compliance standards.
They are implemented by using service control policies and IAM permissions boundaries.
```
G 34


```
Detective guardrails detect policy violations and compliance issues, and generate alerts
for remediation. They are implemented by using AWS Config, AWS Security Hub, Amazon
GuardDuty, AWS Trusted Advisor, Amazon Inspector, and custom AWS Lambda checks.
```
### H.....................................................................................................................................................................

##### HA

```
See high availability.
```
heterogeneous database migration

```
Migrating your source database to a target database that uses a different database engine
(for example, Oracle to Amazon Aurora). Heterogeneous migration is typically part of a re-
architecting effort, and converting the schema can be a complex task. AWS provides AWS SCT
that helps with schema conversions.
```
high availability (HA)

```
The ability of a workload to operate continuously, without intervention, in the event of
challenges or disasters. HA systems are designed to automatically fail over, consistently deliver
high-quality performance, and handle different loads and failures with minimal performance
impact.
```
historian modernization

```
An approach used to modernize and upgrade operational technology (OT) systems to better
serve the needs of the manufacturing industry. A historian is a type of database that is used to
collect and store data from various sources in a factory.
```
holdout data

```
A portion of historical, labeled data that is withheld from a dataset that is used to train a
machine learning model. You can use holdout data to evaluate the model performance by
comparing the model predictions against the holdout data.
```
homogeneous database migration

```
Migrating your source database to a target database that shares the same database engine
(for example, Microsoft SQL Server to Amazon RDS for SQL Server). Homogeneous migration
is typically part of a rehosting or replatforming effort. You can use native database utilities to
migrate the schema.
```
H 35


hot data

```
Data that is frequently accessed, such as real-time data or recent translational data. This data
typically requires a high-performance storage tier or class to provide fast query responses.
```
hotfix

```
An urgent fix for a critical issue in a production environment. Due to its urgency, a hotfix is
usually made outside of the typical DevOps release workflow.
```
hypercare period

```
Immediately following cutover, the period of time when a migration team manages and
monitors the migrated applications in the cloud in order to address any issues. Typically, this
period is 1–4 days in length. At the end of the hypercare period, the migration team typically
transfers responsibility for the applications to the cloud operations team.
```
### I......................................................................................................................................................................

IaC

```
See infrastructure as code.
```
identity-based policy

```
A policy attached to one or more IAM principals that defines their permissions within the AWS
Cloud environment.
```
idle application

```
An application that has an average CPU and memory usage between 5 and 20 percent over
a period of 90 days. In a migration project, it is common to retire these applications or retain
them on premises.
```
IIoT

```
See industrial Internet of Things.
```
immutable infrastructure

```
A model that deploys new infrastructure for production workloads instead of updating,
patching, or modifying the existing infrastructure. Immutable infrastructures are inherently
more consistent, reliable, and predictable than mutable infrastructure. For more information,
see the Deploy using immutable infrastructure best practice in the AWS Well-Architected
Framework.
```
I 36


inbound (ingress) VPC

```
In an AWS multi-account architecture, a VPC that accepts, inspects, and routes network
connections from outside an application. The AWS Security Reference Architecture recommends
setting up your Network account with inbound, outbound, and inspection VPCs to protect the
two-way interface between your application and the broader internet.
```
incremental migration

```
A cutover strategy in which you migrate your application in small parts instead of performing
a single, full cutover. For example, you might move only a few microservices or users to the
new system initially. After you verify that everything is working properly, you can incrementally
move additional microservices or users until you can decommission your legacy system. This
strategy reduces the risks associated with large migrations.
```
Industry 4.0

```
A term that was introduced by Klaus Schwab in 2016 to refer to the modernization of
manufacturing processes through advances in connectivity, real-time data, automation,
analytics, and AI/ML.
```
infrastructure

```
All of the resources and assets contained within an application’s environment.
```
infrastructure as code (IaC)

```
The process of provisioning and managing an application’s infrastructure through a set
of configuration files. IaC is designed to help you centralize infrastructure management,
standardize resources, and scale quickly so that new environments are repeatable, reliable, and
consistent.
```
industrial Internet of Things (IIoT)

```
The use of internet-connected sensors and devices in the industrial sectors, such as
manufacturing, energy, automotive, healthcare, life sciences, and agriculture. For more
information, see Building an industrial Internet of Things (IIoT) digital transformation strategy.
```
inspection VPC

```
In an AWS multi-account architecture, a centralized VPC that manages inspections of network
traffic between VPCs (in the same or different AWS Regions), the internet, and on-premises
networks. The AWS Security Reference Architecture recommends setting up your Network
account with inbound, outbound, and inspection VPCs to protect the two-way interface
between your application and the broader internet.
```
I 37


Internet of Things (IoT)

```
The network of connected physical objects with embedded sensors or processors that
communicate with other devices and systems through the internet or over a local
communication network. For more information, see What is IoT?
```
interpretability

```
A characteristic of a machine learning model that describes the degree to which a human
can understand how the model’s predictions depend on its inputs. For more information, see
Machine learning model interpretability with AWS.
```
IoT

```
See Internet of Things.
```
IT information library (ITIL)

```
A set of best practices for delivering IT services and aligning these services with business
requirements. ITIL provides the foundation for ITSM.
```
IT service management (ITSM)

```
Activities associated with designing, implementing, managing, and supporting IT services for
an organization. For information about integrating cloud operations with ITSM tools, see the
operations integration guide.
```
ITIL

```
See IT information library.
```
ITSM

```
See IT service management.
```
## L.....................................................................................................................................................................

label-based access control (LBAC)

```
An implementation of mandatory access control (MAC) where the users and the data itself are
each explicitly assigned a security label value. The intersection between the user security label
and data security label determines which rows and columns can be seen by the user.
```
L 38


landing zone

```
A landing zone is a well-architected, multi-account AWS environment that is scalable and
secure. This is a starting point from which your organizations can quickly launch and deploy
workloads and applications with confidence in their security and infrastructure environment.
For more information about landing zones, see Setting up a secure and scalable multi-account
AWS environment.
```
large language model (LLM)

```
A deep learning AI model that is pretrained on a vast amount of data. An LLM can perform
multiple tasks, such as answering questions, summarizing documents, translating text into
other languages, and completing sentences. For more information, see What are LLMs.
```
large migration

```
A migration of 300 or more servers.
```
LBAC

```
See label-based access control.
```
least privilege

```
The security best practice of granting the minimum permissions required to perform a task. For
more information, see Apply least-privilege permissions in the IAM documentation.
```
lift and shift

```
See 7 Rs.
```
little-endian system

```
A system that stores the least significant byte first. See also endianness.
```
LLM

```
See large language model.
```
lower environments

```
See environment.
```
L 39


## M....................................................................................................................................................................

machine learning (ML)

```
A type of artificial intelligence that uses algorithms and techniques for pattern recognition and
learning. ML analyzes and learns from recorded data, such as Internet of Things (IoT) data, to
generate a statistical model based on patterns. For more information, see Machine Learning.
```
main branch

```
See branch.
```
malware

```
Software that is designed to compromise computer security or privacy. Malware might disrupt
computer systems, leak sensitive information, or gain unauthorized access. Examples of
malware include viruses, worms, ransomware, Trojan horses, spyware, and keyloggers.
```
managed services

```
AWS services for which AWS operates the infrastructure layer, the operating system, and
platforms, and you access the endpoints to store and retrieve data. Amazon Simple Storage
Service (Amazon S3) and Amazon DynamoDB are examples of managed services. These are also
known as abstracted services.
```
manufacturing execution system (MES)

```
A software system for tracking, monitoring, documenting, and controlling production processes
that convert raw materials to finished products on the shop floor.
```
MAP

```
See Migration Acceleration Program.
```
mechanism

```
A complete process in which you create a tool, drive adoption of the tool, and then inspect the
results in order to make adjustments. A mechanism is a cycle that reinforces and improves itself
as it operates. For more information, see Building mechanisms in the AWS Well-Architected
Framework.
```
member account

```
All AWS accounts other than the management account that are part of an organization in AWS
Organizations. An account can be a member of only one organization at a time.
```
M 40


##### MES

```
See manufacturing execution system.
```
Message Queuing Telemetry Transport (MQTT)

```
A lightweight, machine-to-machine (M2M) communication protocol, based on the publish/
subscribe pattern, for resource-constrained IoT devices.
```
microservice

```
A small, independent service that communicates over well-defined APIs and is typically
owned by small, self-contained teams. For example, an insurance system might include
microservices that map to business capabilities, such as sales or marketing, or subdomains,
such as purchasing, claims, or analytics. The benefits of microservices include agility, flexible
scaling, easy deployment, reusable code, and resilience. For more information, see Integrating
microservices by using AWS serverless services.
```
microservices architecture

```
An approach to building an application with independent components that run each application
process as a microservice. These microservices communicate through a well-defined interface
by using lightweight APIs. Each microservice in this architecture can be updated, deployed,
and scaled to meet demand for specific functions of an application. For more information, see
Implementing microservices on AWS.
```
Migration Acceleration Program (MAP)

```
An AWS program that provides consulting support, training, and services to help organizations
build a strong operational foundation for moving to the cloud, and to help offset the initial
cost of migrations. MAP includes a migration methodology for executing legacy migrations in a
methodical way and a set of tools to automate and accelerate common migration scenarios.
```
migration at scale

```
The process of moving the majority of the application portfolio to the cloud in waves, with
more applications moved at a faster rate in each wave. This phase uses the best practices and
lessons learned from the earlier phases to implement a migration factory of teams, tools, and
processes to streamline the migration of workloads through automation and agile delivery. This
is the third phase of the AWS migration strategy.
```
migration factory

```
Cross-functional teams that streamline the migration of workloads through automated, agile
approaches. Migration factory teams typically include operations, business analysts and owners,
```
M 41


```
migration engineers, developers, and DevOps professionals working in sprints. Between 20
and 50 percent of an enterprise application portfolio consists of repeated patterns that can
be optimized by a factory approach. For more information, see the discussion of migration
factories and the Cloud Migration Factory guide in this content set.
```
migration metadata

```
The information about the application and server that is needed to complete the migration.
Each migration pattern requires a different set of migration metadata. Examples of migration
metadata include the target subnet, security group, and AWS account.
```
migration pattern

```
A repeatable migration task that details the migration strategy, the migration destination, and
the migration application or service used. Example: Rehost migration to Amazon EC2 with AWS
Application Migration Service.
```
Migration Portfolio Assessment (MPA)

```
An online tool that provides information for validating the business case for migrating to
the AWS Cloud. MPA provides detailed portfolio assessment (server right-sizing, pricing, TCO
comparisons, migration cost analysis) as well as migration planning (application data analysis
and data collection, application grouping, migration prioritization, and wave planning). The
MPA tool (requires login) is available free of charge to all AWS consultants and APN Partner
consultants.
```
Migration Readiness Assessment (MRA)

```
The process of gaining insights about an organization’s cloud readiness status, identifying
strengths and weaknesses, and building an action plan to close identified gaps, using the AWS
CAF. For more information, see the migration readiness guide. MRA is the first phase of the AWS
migration strategy.
```
migration strategy

```
The approach used to migrate a workload to the AWS Cloud. For more information, see the 7 Rs
entry in this glossary and see Mobilize your organization to accelerate large-scale migrations.
```
ML

```
See machine learning.
```
M 42


modernization

```
Transforming an outdated (legacy or monolithic) application and its infrastructure into an agile,
elastic, and highly available system in the cloud to reduce costs, gain efficiencies, and take
advantage of innovations. For more information, see Strategy for modernizing applications in
the AWS Cloud.
```
modernization readiness assessment

```
An evaluation that helps determine the modernization readiness of an organization’s
applications; identifies benefits, risks, and dependencies; and determines how well the
organization can support the future state of those applications. The outcome of the assessment
is a blueprint of the target architecture, a roadmap that details development phases and
milestones for the modernization process, and an action plan for addressing identified gaps. For
more information, see Evaluating modernization readiness for applications in the AWS Cloud.
```
monolithic applications (monoliths)

```
Applications that run as a single service with tightly coupled processes. Monolithic applications
have several drawbacks. If one application feature experiences a spike in demand, the
entire architecture must be scaled. Adding or improving a monolithic application’s features
also becomes more complex when the code base grows. To address these issues, you can
use a microservices architecture. For more information, see Decomposing monoliths into
microservices.
```
MPA

```
See Migration Portfolio Assessment.
```
MQTT

```
See Message Queuing Telemetry Transport.
```
multiclass classification

```
A process that helps generate predictions for multiple classes (predicting one of more than
two outcomes). For example, an ML model might ask "Is this product a book, car, or phone?" or
"Which product category is most interesting to this customer?"
```
mutable infrastructure

```
A model that updates and modifies the existing infrastructure for production workloads. For
improved consistency, reliability, and predictability, the AWS Well-Architected Framework
recommends the use of immutable infrastructure as a best practice.
```
M 43


## O....................................................................................................................................................................

##### OAC

```
See origin access control.
```
OAI

```
See origin access identity.
```
OCM

```
See organizational change management.
```
offline migration

```
A migration method in which the source workload is taken down during the migration process.
This method involves extended downtime and is typically used for small, non-critical workloads.
```
OI

```
See operations integration.
```
OLA

```
See operational-level agreement.
```
online migration

```
A migration method in which the source workload is copied to the target system without being
taken offline. Applications that are connected to the workload can continue to function during
the migration. This method involves zero to minimal downtime and is typically used for critical
production workloads.
```
OPC-UA

```
See Open Process Communications - Unified Architecture.
```
Open Process Communications - Unified Architecture (OPC-UA)

```
A machine-to-machine (M2M) communication protocol for industrial automation. OPC-UA
provides an interoperability standard with data encryption, authentication, and authorization
schemes.
```
operational-level agreement (OLA)

```
An agreement that clarifies what functional IT groups promise to deliver to each other, to
support a service-level agreement (SLA).
```
O 44


operational readiness review (ORR)

```
A checklist of questions and associated best practices that help you understand, evaluate,
prevent, or reduce the scope of incidents and possible failures. For more information, see
Operational Readiness Reviews (ORR) in the AWS Well-Architected Framework.
```
operational technology (OT)

```
Hardware and software systems that work with the physical environment to control industrial
operations, equipment, and infrastructure. In manufacturing, the integration of OT and
information technology (IT) systems is a key focus for Industry 4.0 transformations.
```
operations integration (OI)

```
The process of modernizing operations in the cloud, which involves readiness planning,
automation, and integration. For more information, see the operations integration guide.
```
organization trail

```
A trail that’s created by AWS CloudTrail that logs all events for all AWS accounts in an
organization in AWS Organizations. This trail is created in each AWS account that’s part of the
organization and tracks the activity in each account. For more information, see Creating a trail
for an organization in the CloudTrail documentation.
```
organizational change management (OCM)

```
A framework for managing major, disruptive business transformations from a people, culture,
and leadership perspective. OCM helps organizations prepare for, and transition to, new
systems and strategies by accelerating change adoption, addressing transitional issues, and
driving cultural and organizational changes. In the AWS migration strategy, this framework is
called people acceleration , because of the speed of change required in cloud adoption projects.
For more information, see the OCM guide.
```
origin access control (OAC)

```
In CloudFront, an enhanced option for restricting access to secure your Amazon Simple Storage
Service (Amazon S3) content. OAC supports all S3 buckets in all AWS Regions, server-side
encryption with AWS KMS (SSE-KMS), and dynamic PUT and DELETE requests to the S3 bucket.
```
origin access identity (OAI)

```
In CloudFront, an option for restricting access to secure your Amazon S3 content. When you
use OAI, CloudFront creates a principal that Amazon S3 can authenticate with. Authenticated
principals can access content in an S3 bucket only through a specific CloudFront distribution.
See also OAC, which provides more granular and enhanced access control.
```
O 45


##### ORR

```
See operational readiness review.
```
OT

```
See operational technology.
```
outbound (egress) VPC

```
In an AWS multi-account architecture, a VPC that handles network connections that are
initiated from within an application. The AWS Security Reference Architecture recommends
setting up your Network account with inbound, outbound, and inspection VPCs to protect the
two-way interface between your application and the broader internet.
```
## P.....................................................................................................................................................................

permissions boundary

```
An IAM management policy that is attached to IAM principals to set the maximum permissions
that the user or role can have. For more information, see Permissions boundaries in the IAM
documentation.
```
personally identifiable information (PII)

```
Information that, when viewed directly or paired with other related data, can be used to
reasonably infer the identity of an individual. Examples of PII include names, addresses, and
contact information.
```
PII

```
See personally identifiable information.
```
playbook

```
A set of predefined steps that capture the work associated with migrations, such as delivering
core operations functions in the cloud. A playbook can take the form of scripts, automated
runbooks, or a summary of processes or steps required to operate your modernized
environment.
```
PLC

```
See programmable logic controller.
```
P 46


##### PLM

```
See product lifecycle management.
```
policy

```
An object that can define permissions (see identity-based policy), specify access conditions (see
resource-based policy), or define the maximum permissions for all accounts in an organization
in AWS Organizations (see service control policy).
```
polyglot persistence

```
Independently choosing a microservice’s data storage technology based on data access patterns
and other requirements. If your microservices have the same data storage technology, they can
encounter implementation challenges or experience poor performance. Microservices are more
easily implemented and achieve better performance and scalability if they use the data store
best adapted to their requirements. For more information, see Enabling data persistence in
microservices.
```
portfolio assessment

```
A process of discovering, analyzing, and prioritizing the application portfolio in order to plan
the migration. For more information, see Evaluating migration readiness.
```
predicate

```
A query condition that returns true or false, commonly located in a WHERE clause.
```
predicate pushdown

```
A database query optimization technique that filters the data in the query before transfer. This
reduces the amount of data that must be retrieved and processed from the relational database,
and it improves query performance.
```
preventative control

```
A security control that is designed to prevent an event from occurring. These controls are a first
line of defense to help prevent unauthorized access or unwanted changes to your network. For
more information, see Preventative controls in Implementing security controls on AWS.
```
principal

```
An entity in AWS that can perform actions and access resources. This entity is typically a root
user for an AWS account, an IAM role, or a user. For more information, see Principal in Roles
terms and concepts in the IAM documentation.
```
P 47


privacy by design

```
A system engineering approach that takes privacy into account through the whole development
process.
```
private hosted zones

```
A container that holds information about how you want Amazon Route 53 to respond to DNS
queries for a domain and its subdomains within one or more VPCs. For more information, see
Working with private hosted zones in the Route 53 documentation.
```
proactive control

```
A security control designed to prevent the deployment of noncompliant resources. These
controls scan resources before they are provisioned. If the resource is not compliant with the
control, then it isn't provisioned. For more information, see the Controls reference guide in the
AWS Control Tower documentation and see Proactive controls in Implementing security controls
on AWS.
```
product lifecycle management (PLM)

```
The management of data and processes for a product throughout its entire lifecycle, from
design, development, and launch, through growth and maturity, to decline and removal.
```
production environment

```
See environment.
```
programmable logic controller (PLC)

```
In manufacturing, a highly reliable, adaptable computer that monitors machines and automates
manufacturing processes.
```
prompt chaining

```
Using the output of one LLM prompt as the input for the next prompt to generate better
responses. This technique is used to break down a complex task into subtasks, or to iteratively
refine or expand a preliminary response. It helps improve the accuracy and relevance of a
model’s responses and allows for more granular, personalized results.
```
pseudonymization

```
The process of replacing personal identifiers in a dataset with placeholder values.
Pseudonymization can help protect personal privacy. Pseudonymized data is still considered to
be personal data.
```
P 48


publish/subscribe (pub/sub)

```
A pattern that enables asynchronous communications among microservices to improve
scalability and responsiveness. For example, in a microservices-based MES, a microservice can
publish event messages to a channel that other microservices can subscribe to. The system can
add new microservices without changing the publishing service.
```
## Q....................................................................................................................................................................

query plan

```
A series of steps, like instructions, that are used to access the data in a SQL relational database
system.
```
query plan regression

```
When a database service optimizer chooses a less optimal plan than it did before a given
change to the database environment. This can be caused by changes to statistics, constraints,
environment settings, query parameter bindings, and updates to the database engine.
```
## R.....................................................................................................................................................................

RACI matrix

```
See responsible, accountable, consulted, informed (RACI).
```
RAG

```
See Retrieval Augmented Generation.
```
ransomware

```
A malicious software that is designed to block access to a computer system or data until a
payment is made.
```
RASCI matrix

```
See responsible, accountable, consulted, informed (RACI).
```
RCAC

```
See row and column access control.
```
Q 49


read replica

```
A copy of a database that’s used for read-only purposes. You can route queries to the read
replica to reduce the load on your primary database.
```
re-architect

```
See 7 Rs.
```
recovery point objective (RPO)

```
The maximum acceptable amount of time since the last data recovery point. This determines
what is considered an acceptable loss of data between the last recovery point and the
interruption of service.
```
recovery time objective (RTO)

```
The maximum acceptable delay between the interruption of service and restoration of service.
```
refactor

```
See 7 Rs.
```
Region

```
A collection of AWS resources in a geographic area. Each AWS Region is isolated and
independent of the others to provide fault tolerance, stability, and resilience. For more
information, see Specify which AWS Regions your account can use.
```
regression

```
An ML technique that predicts a numeric value. For example, to solve the problem of "What
price will this house sell for?" an ML model could use a linear regression model to predict a
house's sale price based on known facts about the house (for example, the square footage).
```
rehost

```
See 7 Rs.
```
release

```
In a deployment process, the act of promoting changes to a production environment.
```
relocate

```
See 7 Rs.
```
replatform

```
See 7 Rs.
```
R 50


repurchase

```
See 7 Rs.
```
resiliency

```
An application's ability to resist or recover from disruptions. High availability and disaster
recovery are common considerations when planning for resiliency in the AWS Cloud. For more
information, see AWS Cloud Resilience.
```
resource-based policy

```
A policy attached to a resource, such as an Amazon S3 bucket, an endpoint, or an encryption
key. This type of policy specifies which principals are allowed access, supported actions, and any
other conditions that must be met.
```
responsible, accountable, consulted, informed (RACI) matrix

```
A matrix that defines the roles and responsibilities for all parties involved in migration activities
and cloud operations. The matrix name is derived from the responsibility types defined in the
matrix: responsible (R), accountable (A), consulted (C), and informed (I). The support (S) type
is optional. If you include support, the matrix is called a RASCI matrix , and if you exclude it, it’s
called a RACI matrix.
```
responsive control

```
A security control that is designed to drive remediation of adverse events or deviations from
your security baseline. For more information, see Responsive controls in Implementing security
controls on AWS.
```
retain

```
See 7 Rs.
```
retire

```
See 7 Rs.
```
Retrieval Augmented Generation (RAG)

```
A generative AI technology in which an LLM references an authoritative data source that is
outside of its training data sources before generating a response. For example, a RAG model
might perform a semantic search of an organization's knowledge base or custom data. For more
information, see What is RAG.
```
R 51


rotation

```
The process of periodically updating a secret to make it more difficult for an attacker to access
the credentials.
```
row and column access control (RCAC)

```
The use of basic, flexible SQL expressions that have defined access rules. RCAC consists of row
permissions and column masks.
```
RPO

```
See recovery point objective.
```
RTO

```
See recovery time objective.
```
runbook

```
A set of manual or automated procedures required to perform a specific task. These are
typically built to streamline repetitive operations or procedures with high error rates.
```
## S.....................................................................................................................................................................

##### SAML 2.0

```
An open standard that many identity providers (IdPs) use. This feature enables federated
single sign-on (SSO), so users can log into the AWS Management Console or call the AWS API
operations without you having to create user in IAM for everyone in your organization. For more
information about SAML 2.0-based federation, see About SAML 2.0-based federation in the IAM
documentation.
```
SCADA

```
See supervisory control and data acquisition.
```
SCP

```
See service control policy.
```
secret

```
In AWS Secrets Manager, confidential or restricted information, such as a password or user
credentials, that you store in encrypted form. It consists of the secret value and its metadata.
```
S 52


```
The secret value can be binary, a single string, or multiple strings. For more information, see
What's in a Secrets Manager secret? in the Secrets Manager documentation.
```
security by design

```
A system engineering approach that takes security into account through the whole
development process.
```
security control

```
A technical or administrative guardrail that prevents, detects, or reduces the ability of a threat
actor to exploit a security vulnerability. There are four primary types of security controls:
preventative, detective, responsive, and proactive.
```
security hardening

```
The process of reducing the attack surface to make it more resistant to attacks. This can include
actions such as removing resources that are no longer needed, implementing the security best
practice of granting least privilege, or deactivating unnecessary features in configuration files.
```
security information and event management (SIEM) system

```
Tools and services that combine security information management (SIM) and security event
management (SEM) systems. A SIEM system collects, monitors, and analyzes data from servers,
networks, devices, and other sources to detect threats and security breaches, and to generate
alerts.
```
security response automation

```
A predefined and programmed action that is designed to automatically respond to or remediate
a security event. These automations serve as detective or responsive security controls that help
you implement AWS security best practices. Examples of automated response actions include
modifying a VPC security group, patching an Amazon EC2 instance, or rotating credentials.
```
server-side encryption

```
Encryption of data at its destination, by the AWS service that receives it.
```
service control policy (SCP)

```
A policy that provides centralized control over permissions for all accounts in an organization
in AWS Organizations. SCPs define guardrails or set limits on actions that an administrator can
delegate to users or roles. You can use SCPs as allow lists or deny lists, to specify which services
or actions are permitted or prohibited. For more information, see Service control policies in the
AWS Organizations documentation.
```
S 53


service endpoint

```
The URL of the entry point for an AWS service. You can use the endpoint to connect
programmatically to the target service. For more information, see AWS service endpoints in
AWS General Reference.
```
service-level agreement (SLA)

```
An agreement that clarifies what an IT team promises to deliver to their customers, such as
service uptime and performance.
```
service-level indicator (SLI)

```
A measurement of a performance aspect of a service, such as its error rate, availability, or
throughput.
```
service-level objective (SLO)

```
A target metric that represents the health of a service, as measured by a service-level indicator.
```
shared responsibility model

```
A model describing the responsibility you share with AWS for cloud security and compliance.
AWS is responsible for security of the cloud, whereas you are responsible for security in the
cloud. For more information, see Shared responsibility model.
```
SIEM

```
See security information and event management system.
```
single point of failure (SPOF)

```
A failure in a single, critical component of an application that can disrupt the system.
```
SLA

```
See service-level agreement.
```
SLI

```
See service-level indicator.
```
SLO

```
See service-level objective.
```
split-and-seed model

```
A pattern for scaling and accelerating modernization projects. As new features and product
releases are defined, the core team splits up to create new product teams. This helps scale your
```
S 54


```
organization’s capabilities and services, improves developer productivity, and supports rapid
innovation. For more information, see Phased approach to modernizing applications in the AWS
Cloud.
```
SPOF

```
See single point of failure.
```
star schema

```
A database organizational structure that uses one large fact table to store transactional or
measured data and uses one or more smaller dimensional tables to store data attributes. This
structure is designed for use in a data warehouse or for business intelligence purposes.
```
strangler fig pattern

```
An approach to modernizing monolithic systems by incrementally rewriting and replacing
system functionality until the legacy system can be decommissioned. This pattern uses the
analogy of a fig vine that grows into an established tree and eventually overcomes and replaces
its host. The pattern was introduced by Martin Fowler as a way to manage risk when rewriting
monolithic systems. For an example of how to apply this pattern, see Modernizing legacy
Microsoft ASP.NET (ASMX) web services incrementally by using containers and Amazon API
Gateway.
```
subnet

```
A range of IP addresses in your VPC. A subnet must reside in a single Availability Zone.
```
supervisory control and data acquisition (SCADA)

```
In manufacturing, a system that uses hardware and software to monitor physical assets and
production operations.
```
symmetric encryption

```
An encryption algorithm that uses the same key to encrypt and decrypt the data.
```
synthetic testing

```
Testing a system in a way that simulates user interactions to detect potential issues or to
monitor performance. You can use Amazon CloudWatch Synthetics to create these tests.
```
system prompt

```
A technique for providing context, instructions, or guidelines to an LLM to direct its behavior.
System prompts help set context and establish rules for interactions with users.
```
S 55


## T.....................................................................................................................................................................

tags

```
Key-value pairs that act as metadata for organizing your AWS resources. Tags can help you
manage, identify, organize, search for, and filter resources. For more information, see Tagging
your AWS resources.
```
target variable

```
The value that you are trying to predict in supervised ML. This is also referred to as an outcome
variable. For example, in a manufacturing setting the target variable could be a product defect.
```
task list

```
A tool that is used to track progress through a runbook. A task list contains an overview of
the runbook and a list of general tasks to be completed. For each general task, it includes the
estimated amount of time required, the owner, and the progress.
```
test environment

```
See environment.
```
training

```
To provide data for your ML model to learn from. The training data must contain the correct
answer. The learning algorithm finds patterns in the training data that map the input data
attributes to the target (the answer that you want to predict). It outputs an ML model that
captures these patterns. You can then use the ML model to make predictions on new data for
which you don’t know the target.
```
transit gateway

```
A network transit hub that you can use to interconnect your VPCs and on-premises
networks. For more information, see What is a transit gateway in the AWS Transit Gateway
documentation.
```
trunk-based workflow

```
An approach in which developers build and test features locally in a feature branch and then
merge those changes into the main branch. The main branch is then built to the development,
preproduction, and production environments, sequentially.
```
T 56


trusted access

```
Granting permissions to a service that you specify to perform tasks in your organization in AWS
Organizations and in its accounts on your behalf. The trusted service creates a service-linked
role in each account, when that role is needed, to perform management tasks for you. For more
information, see Using AWS Organizations with other AWS services in the AWS Organizations
documentation.
```
tuning

```
To change aspects of your training process to improve the ML model's accuracy. For example,
you can train the ML model by generating a labeling set, adding labels, and then repeating
these steps several times under different settings to optimize the model.
```
two-pizza team

```
A small DevOps team that you can feed with two pizzas. A two-pizza team size ensures the best
possible opportunity for collaboration in software development.
```
## U.....................................................................................................................................................................

uncertainty

```
A concept that refers to imprecise, incomplete, or unknown information that can undermine the
reliability of predictive ML models. There are two types of uncertainty: Epistemic uncertainty
is caused by limited, incomplete data, whereas aleatoric uncertainty is caused by the noise and
randomness inherent in the data. For more information, see the Quantifying uncertainty in
deep learning systems guide.
```
undifferentiated tasks

```
Also known as heavy lifting , work that is necessary to create and operate an application but
that doesn’t provide direct value to the end user or provide competitive advantage. Examples of
undifferentiated tasks include procurement, maintenance, and capacity planning.
```
upper environments

```
See environment.
```
U 57


## V.....................................................................................................................................................................

vacuuming

```
A database maintenance operation that involves cleaning up after incremental updates to
reclaim storage and improve performance.
```
version control

```
Processes and tools that track changes, such as changes to source code in a repository.
```
VPC peering

```
A connection between two VPCs that allows you to route traffic by using private IP addresses.
For more information, see What is VPC peering in the Amazon VPC documentation.
```
vulnerability

```
A software or hardware flaw that compromises the security of the system.
```
## W....................................................................................................................................................................

warm cache

```
A buffer cache that contains current, relevant data that is frequently accessed. The database
instance can read from the buffer cache, which is faster than reading from the main memory or
disk.
```
warm data

```
Data that is infrequently accessed. When querying this kind of data, moderately slow queries
are typically acceptable.
```
window function

```
A SQL function that performs a calculation on a group of rows that relate in some way to the
current record. Window functions are useful for processing tasks, such as calculating a moving
average or accessing the value of rows based on the relative position of the current row.
```
workload

```
A collection of resources and code that delivers business value, such as a customer-facing
application or backend process.
```
V 58


workstream

```
Functional groups in a migration project that are responsible for a specific set of tasks. Each
workstream is independent but supports the other workstreams in the project. For example,
the portfolio workstream is responsible for prioritizing applications, wave planning, and
collecting migration metadata. The portfolio workstream delivers these assets to the migration
workstream, which then migrates the servers and applications.
```
WORM

```
See write once, read many.
```
WQF

```
See AWS Workload Qualification Framework.
```
write once, read many (WORM)

```
A storage model that writes data a single time and prevents the data from being deleted or
modified. Authorized users can read the data as many times as needed, but they cannot change
it. This data storage infrastructure is considered immutable.
```
## Z.....................................................................................................................................................................

zero-day exploit

```
An attack, typically malware, that takes advantage of a zero-day vulnerability.
```
zero-day vulnerability

```
An unmitigated flaw or vulnerability in a production system. Threat actors can use this type of
vulnerability to attack the system. Developers frequently become aware of the vulnerability as a
result of the attack.
```
zero-shot prompting

```
Providing an LLM with instructions for performing a task but no examples ( shots ) that can help
guide it. The LLM must use its pre-trained knowledge to handle the task. The effectiveness of
zero-shot prompting depends on the complexity of the task and the quality of the prompt. See
also few-shot prompting.
```
zombie application

```
An application that has an average CPU and memory usage below 5 percent. In a migration
project, it is common to retire these applications.
```
Z 59


