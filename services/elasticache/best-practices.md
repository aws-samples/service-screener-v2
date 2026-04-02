# Amazon ElastiCache Best Practices

This document outlines best practices for Amazon ElastiCache based on official AWS documentation.

## Overall Best Practices

### Use Cluster-Mode Enabled Configurations
- Enable cluster mode for horizontal scaling
- Achieve higher storage and throughput
- ElastiCache Serverless requires cluster-mode enabled
- Scale beyond single-node limitations

**Reference:** [Overall best practices](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/WorkingWithRedis.html)

### Use Long-Lived Connections
- Reuse connections instead of creating new ones
- Use connection pooling to amortize connection costs
- Reduce CPU resources spent on connection creation
- Improve overall performance

**Reference:** [Overall best practices](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/WorkingWithRedis.html)

### Read from Replicas
- Direct read operations to replicas for better scalability
- Reduce latency by reading from geographically closer replicas
- Offload read traffic from primary node
- Accept eventual consistency for read operations

**Important:** Configure clients to read from at least two replicas or one replica plus primary to handle node failures.

**Reference:** [Overall best practices](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/WorkingWithRedis.html)

### Avoid Expensive Commands
- Don't use KEYS or SMEMBERS commands
- Use SCAN and SSCAN instead
- Avoid computationally intensive operations
- Prevent performance degradation

**Reference:** [Overall best practices](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/WorkingWithRedis.html)

### Follow Lua Script Best Practices
- Avoid long-running Lua scripts
- Declare keys used in scripts upfront
- Ensure keys belong to same slot
- Prevent cross-slot command issues

**Reference:** [Overall best practices](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/WorkingWithRedis.html)

### Use Sharded Pub/Sub
- Use sharded pub/sub for high throughput workloads
- Available with Valkey and Redis OSS 7+
- Avoid high EngineCPUUtilization from traditional pub/sub
- ElastiCache Serverless uses sharded pub/sub internally

**Reference:** [Overall best practices](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/WorkingWithRedis.html)

## Read Replica Best Practices

### Understand Eventual Consistency
- Read replicas provide eventual consistency
- Acceptable for session stores, leaderboards, recommendations
- Replication typically completes within milliseconds
- Balance consistency requirements with performance

**Reference:** [Best Practices for using Read Replicas](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/ReadReplicas.html)

### Use Primary Endpoint for Strong Consistency
- Use primary endpoint (port 6379) for immediate consistency
- Required for write operations
- Best for critical transactions
- Guarantees most up-to-date data

**Reference:** [Best Practices for using Read Replicas](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/ReadReplicas.html)

### Use Latency Optimized Endpoint
- Use port 6380 for read operations with eventual consistency
- Automatically routes to local Availability Zone replica
- Reduces network latency
- Falls back to other zones during failures

**Reference:** [Best Practices for using Read Replicas](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/ReadReplicas.html)

### Distribute Read Traffic
- Distribute reads across multiple replica nodes
- Offload read traffic from primary
- Reduce connection overhead on primary
- Improve write performance during peak traffic

**Reference:** [Best Practices for using Read Replicas](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/ReadReplicas.html)

## Client Best Practices

### Manage Connection Count
- Limit number of connections per client
- Use connection pooling
- Monitor connection metrics
- Avoid connection exhaustion

**Reference:** [Best practices for clients (Valkey and Redis OSS)](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/BestPractices.Clients.redis.html)

### Implement Cluster Client Discovery
- Use cluster-aware clients for automatic node discovery
- Handle cluster topology changes
- Implement exponential backoff for retries
- Monitor cluster slots for topology updates

**Reference:** [Best practices for clients (Valkey and Redis OSS)](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/BestPractices.Clients.redis.html)

### Configure Client-Side Timeouts
- Set appropriate client-side timeouts
- Prevent indefinite blocking
- Handle slow operations gracefully
- Balance timeout with operation requirements

**Reference:** [Best practices for clients (Valkey and Redis OSS)](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/BestPractices.Clients.redis.html)

### Configure Server-Side Idle Timeouts
- Set server-side idle timeout appropriately
- Close inactive connections
- Free up resources
- Prevent connection leaks

**Reference:** [Best practices for clients (Valkey and Redis OSS)](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/BestPractices.Clients.redis.html)

### Handle Large Composite Items
- Break large items into smaller chunks
- Use compression for large values
- Consider data structure design
- Avoid exceeding value size limits

**Reference:** [Best practices for clients (Valkey and Redis OSS)](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/BestPractices.Clients.redis.html)

## Performance Best Practices

### Leverage Parallelism
- Distribute workload across clients and directories
- Use multiple threads per client
- Minimize contention between threads
- Achieve higher throughput and IOPS

**Reference:** [Amazon ElastiCache Well-Architected Lens Performance Efficiency Pillar](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/PerformanceEfficiencyPillar.html)

### Monitor Cluster Performance
- Track CPU, memory, and network metrics
- Monitor cache hit ratio
- Identify performance bottlenecks
- Use CloudWatch for monitoring

**Reference:** [Amazon ElastiCache Well-Architected Lens Performance Efficiency Pillar](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/PerformanceEfficiencyPillar.html)

### Optimize Key Distribution
- Distribute keys uniformly across shards
- Avoid hot keys
- Use consistent hashing
- Balance load across nodes

**Reference:** [Common troubleshooting steps and best practices with ElastiCache](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/wwe-troubleshooting.html)

### Log Slow Commands
- Enable slow log to identify performance issues
- Monitor command execution times
- Optimize slow operations
- Improve overall performance

**Reference:** [Amazon ElastiCache Well-Architected Lens Performance Efficiency Pillar](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/PerformanceEfficiencyPillar.html)

### Implement Auto Scaling
- Configure auto scaling for dynamic workloads
- Scale based on metrics like CPU and memory
- Optimize resource utilization
- Reduce costs during low usage

**Reference:** [Amazon ElastiCache Well-Architected Lens Performance Efficiency Pillar](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/PerformanceEfficiencyPillar.html)

## Reliability Best Practices

### Deploy Multi-AZ Configurations
- Enable Multi-AZ for high availability
- Automatic failover to replica nodes
- Protect against Availability Zone failures
- Minimize downtime

**Reference:** [Amazon ElastiCache Well-Architected Lens Reliability Pillar](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/ReliabilityPillar.html)

### Use Global Datastores
- Replicate data across regions
- Enable disaster recovery
- Reduce latency for global users
- Support business continuity

**Reference:** [Amazon ElastiCache Well-Architected Lens Reliability Pillar](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/ReliabilityPillar.html)

### Implement Backup and Restore
- Create regular snapshots
- Test restore procedures
- Define recovery objectives (RTO/RPO)
- Automate backup schedules

**Reference:** [Amazon ElastiCache Well-Architected Lens Reliability Pillar](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/ReliabilityPillar.html)

### Plan for Failover
- Test failover procedures regularly
- Configure appropriate failover settings
- Monitor failover metrics
- Document failover processes

**Reference:** [Amazon ElastiCache Well-Architected Lens Reliability Pillar](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/ReliabilityPillar.html)

### Scale Clusters Appropriately
- Plan for capacity requirements
- Scale vertically (node size) or horizontally (shards)
- Monitor resource utilization
- Avoid resource exhaustion

**Reference:** [Amazon ElastiCache Well-Architected Lens Reliability Pillar](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/ReliabilityPillar.html)

## Troubleshooting Best Practices

### Reuse Connections
- Avoid creating new connections for each request
- Use connection pooling
- Reduce connection overhead
- Improve performance

**Reference:** [Common troubleshooting steps and best practices with ElastiCache](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/wwe-troubleshooting.html)

### Distribute Keys Uniformly
- Ensure even key distribution across shards
- Avoid hot spots
- Balance load across cluster
- Optimize resource utilization

**Reference:** [Common troubleshooting steps and best practices with ElastiCache](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/wwe-troubleshooting.html)

### Enable Read Replicas for Serverless
- Configure read replicas for better performance
- Reduce latency for read operations
- Improve scalability
- Handle higher read throughput

**Reference:** [Common troubleshooting steps and best practices with ElastiCache](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/wwe-troubleshooting.html)

## Additional Resources

- [Amazon ElastiCache User Guide](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/)
- [Amazon ElastiCache API Reference](https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/)
- [Database Caching Strategies Using Redis](https://docs.aws.amazon.com/whitepapers/latest/database-caching-strategies-using-redis/)
- [Performance at Scale with Amazon ElastiCache](https://docs.aws.amazon.com/whitepapers/latest/performance-at-scale-with-amazon-elasticache/)
