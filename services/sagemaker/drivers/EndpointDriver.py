import botocore

from services.Evaluator import Evaluator


class EndpointDriver(Evaluator):
    def __init__(self, endpoint, sagemakerClient, autoscalingClient):
        super().__init__()
        self.endpoint = endpoint
        self.sagemakerClient = sagemakerClient
        self.autoscalingClient = autoscalingClient
        self.init()
    
    def _checkEndpointAutoScalingConfigured(self):
        """
        Check if endpoint has auto-scaling configured for production variants.
        
        Auto-scaling helps:
        - Handle traffic spikes automatically
        - Reduce costs during low traffic periods
        - Maintain steady performance
        
        PASS: At least one variant has auto-scaling configured
        FAIL: No variants have auto-scaling configured
        """
        endpointName = self.endpoint['EndpointName']
        variants = self.endpoint.get('ProductionVariants', [])
        
        if not variants:
            self.results['EndpointAutoScalingConfigured'] = [-1, 'No production variants found']
            return
        
        # Check each variant for auto-scaling configuration
        variants_with_autoscaling = []
        variants_without_autoscaling = []
        
        for variant in variants:
            variantName = variant['VariantName']
            resourceId = f'endpoint/{endpointName}/variant/{variantName}'
            
            try:
                # Check if this variant has auto-scaling configured
                response = self.autoscalingClient.describe_scalable_targets(
                    ServiceNamespace='sagemaker',
                    ResourceIds=[resourceId]
                )
                
                if response.get('ScalableTargets'):
                    variants_with_autoscaling.append(variantName)
                else:
                    variants_without_autoscaling.append(variantName)
                    
            except botocore.exceptions.ClientError as e:
                # If resource not found, auto-scaling is not configured
                if e.response['Error']['Code'] in ['ValidationException', 'ResourceNotFoundException']:
                    variants_without_autoscaling.append(variantName)
                else:
                    # Other errors - treat as not configured
                    variants_without_autoscaling.append(variantName)
        
        # Result: PASS if at least one variant has auto-scaling
        if variants_with_autoscaling:
            self.results['EndpointAutoScalingConfigured'] = [
                1,
                f'Auto-scaling configured for variants: {", ".join(variants_with_autoscaling)}'
            ]
        else:
            self.results['EndpointAutoScalingConfigured'] = [
                -1,
                f'No auto-scaling configured for any variant. Consider enabling auto-scaling for: {", ".join(variants_without_autoscaling)}'
            ]
    
    def _checkVariantWeightDistribution(self):
        """
        Check if endpoint has multiple variants with balanced traffic distribution.
        
        Multiple variants enable:
        - A/B testing of different models
        - Gradual rollout of new models
        - Performance comparison
        
        PASS: Multiple variants with traffic distribution
        INFO: Single variant or unbalanced distribution (advisory)
        """
        endpointName = self.endpoint['EndpointName']
        variants = self.endpoint.get('ProductionVariants', [])
        
        if not variants:
            self.results['EndpointVariantWeightDistribution'] = [-1, 'No production variants found']
            return
        
        if len(variants) == 1:
            variantName = variants[0]['VariantName']
            self.results['EndpointVariantWeightDistribution'] = [
                -1,
                f'Single variant ({variantName}). Consider using multiple variants for A/B testing'
            ]
            return
        
        # Check traffic distribution
        variantWeights = []
        totalWeight = 0
        
        for variant in variants:
            variantName = variant['VariantName']
            currentWeight = variant.get('CurrentWeight', 0)
            desiredWeight = variant.get('DesiredWeight', 0)
            weight = currentWeight if currentWeight > 0 else desiredWeight
            
            variantWeights.append((variantName, weight))
            totalWeight += weight
        
        # Check if weights are balanced (within 20% of equal distribution)
        if totalWeight > 0:
            expectedWeight = totalWeight / len(variants)
            threshold = expectedWeight * 0.2  # 20% tolerance
            
            unbalanced = []
            balanced = []
            
            for variantName, weight in variantWeights:
                if abs(weight - expectedWeight) > threshold:
                    unbalanced.append(f"{variantName}({weight:.1f})")
                else:
                    balanced.append(f"{variantName}({weight:.1f})")
            
            if unbalanced:
                self.results['EndpointVariantWeightDistribution'] = [
                    -1,
                    f'Unbalanced traffic distribution: {", ".join([f"{n}({w:.1f})" for n, w in variantWeights])}'
                ]
            else:
                self.results['EndpointVariantWeightDistribution'] = [
                    1,
                    f'Balanced traffic across {len(variants)} variants: {", ".join([f"{n}({w:.1f})" for n, w in variantWeights])}'
                ]
        else:
            self.results['EndpointVariantWeightDistribution'] = [
                -1,
                f'{len(variants)} variants configured but no traffic weights set'
            ]

