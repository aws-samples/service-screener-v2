# reporter.json
## Syntax
```json
{
	"<CHECK_NAME>": {
		"category": '<ENUM>', 		//REQUIRED, valid value (combination): O,S,R,P,C
		"^description": '<string>', //REQUIRED
		"shortDesc": '<string>', 	//OPTIONAL
		"criticality": '<ENUM>', 	//REQUIRED, valid value (single): I, L, M, H
		"downtime": '<int>', 		//OPTIONAL
		"slowness": '<int>', 		//OPTIONAL
		"additionalCost": '<int>', 	//OPTIONAL
		"needFullTest": '<int>', 	//OPTIONAL
		"ref": [					//OPTIONAL
			"[<text_to_display>]<url>",
			"[<text_to_display>]<url>",
		],
	}
}
```

## Parameter Details
### CHECK_NAME
`Required: Yes`
`Type: string`

The check_name performed by service-->driver, and stored in $this->result

### category
`Required: Yes`
`Type: ENUM`

Indicate which [AWS Well Architecture Pillar](https://aws.amazon.com/architecture/well-architected/?wa-lens-whitepapers.sort-by=item.additionalFields.sortDate&wa-lens-whitepapers.sort-order=desc) this check is referring to. The valid values are (combination). First character in the string will be the MAIN pillar of the CHECK.

- O: Operation Excellence
- S: Security
- R: Reliability
- P: Performance Efficiency
- C: Cost Optimization

Example: 

`"category" : "RS"` refers to both Security & Reliability.  Reliability being the main pillar.

`"category" : "CPO"`: refers to Cost Optimization, Performance Efficiency, Operation Excellence. Cost being the main pillar

`"category" : "S"`: refers to Security only. Security itself being the main pillar.


### ^description
`Required: Yes`
`Type: string`

CHECK description, often use in report summary to explain the purpose of the check, number of resources affected by this CHECK, and recommendation. This field is supported by various keywords.

Example: `"^description": "You have {$COUNT}  production instances which are not configure to be tolerant to issues in an Availability Zone."`

Keyword: 
`{$COUNT}` will be converted to number of resources affected by this CHECK.


### shortDesc
`Type: string`

CHECK short description, often use in report detail table format.

Example: `Turn on Multi-AZ`


### criticality
`Required: Yes`
`Type: ENUM`

This indicate the severity of the CHECK. The supported values are (single value only:

- I: Informational
- L: Low Risk
- M: Medium Risk
- H: High Risk

Example: `"criticality" :  "H"`

### downtime
`Type: int`

This indicate if this CHECK required down time upon perform the changes. Valid values are:

- 0: No downtime required
- 1: Downtime required
- -1: It depends

Example: `"downtime" : -1`

### slowness
`Type: int`

This indicate if this CHECK impact resource performance during the period of change . Valid values are:

- 0: No impact to performance
- 1: Performance will be impacted
- -1: It depends

Example: `"slowness" : -1`


### additionalCost
`Type: int`

This indicate if this changes made on this CHECK will incur additional cost. Valid values are:

- 0: No additional cost will be incurred
- 1: Additional cost will be incurred
- -1: It depends

Example: `"additionalCost" : -1`


### needFullTest
`Type: int`

This indicate if this changes made on this CHECK will required to perform application testing. Valid values are:

- 0: No additional test is required
- 1: Additional test will be required
- -1: It depends

Example: `"needFullTest" : -1`


### ref
`Type: list`

Provide external resources, such as external blogs or AWS documentations related to this CHECK.

Example: 
```
"ref": [
	"[Google]<https://www.google.com>",
	"[AWS Blog]<https://aws.amazon.com/blogs/aws/>"
]
```


## Example
```json
{
    "MultiAZ": {
        "category": "RO",
        "^description": "High Availability: You have {$COUNT} production instances/clusters which are not configured to be tolerant to issues in an Availability Zone. Reconfigure production RDS instances to Multi-AZ. For Aurora clusters, have at least 2 instances (each in a different availability zone). Enabling multi-AZ for RDS cluster and adding another instance will lead to additional cost. Converting single-AZ instance to multi-AZ instance will avoid downtime but you can experience performance impact. You should perform this operations during off-peak hours. You can also create a multi-AZ read replica and then perform a failover.",
        "downtime": -1,
        "slowness": -1,
        "additionalCost": 1,
        "needFullTest": 0,
        "criticality": "H",
        "shortDesc": "Enable MultiAZ",
        "ref": [
			"[Google]<https://www.google.com>",
			"[AWS Blog]<https://aws.amazon.com/blogs/aws/>"
		]
    },
    "EngineVersionMajor": {
        "category": "SP",
        "^description": "Version Currency: {$COUNT} of your instances/cluster are on older version. Upgrade to latest version to get access to new features. You should perform proper testing before upgrading the production environment. There are different options to perform major version upgrade and your choices will depend on architecture, schema and workload. If you choose to upgrade by setting up replication, you may incur additional cost for replication (e.g. when using DMS) and for additional instance.",
        "downtime": 1,
        "slowness": 0,
        "additionalCost": 0,
        "needFullTest": 1,
        "criticality": "H",
        "shortDesc": "Major version available",
        "ref": [
			"[Google]<https://www.google.com>",
			"[AWS Blog]<https://aws.amazon.com/blogs/aws/>"
		]
    }
}
```


## Template
```json
{
    "CHECKNAME": {
        "category": "OSRPC",
        "^description": "Sample {$COUNT} continue",
        "downtime": -1,
        "slowness": -1,
        "additionalCost": 1,
        "criticality": "H",
        "needFullTest": 0,
        "shortDesc": "Enable MultiAZ",
        "ref": [
			"[Google]<https://www.google.com>",
			"[AWS Blog]<https://aws.amazon.com/blogs/aws/>"
		]
    }
}
```