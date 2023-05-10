from setuptools import setup, find_packages
setup(
    name='ServiceScreenerV2', 
    version='2.0',
    author='AWS Service Screener',
    author_email='aws-gh-ss@amazon.com',
    url='https://github.com/aws-samples/service-screener-v2/',
    description='An open source guidance tool for AWS environments',
    long_description='Service Screener is an open source tool that runs automated checks on AWS environments and provide recommendations based on the AWS Well Architected Framework. AWS customers can use this tool on their own environments and use the recommendations to improve the Security, Reliability, Operational Excellence, Performance Efficiency and Cost Optimisation of their workloads. This tool aims to complement the AWS Well Architected Tool.',
    license='Apache 2.0 license',
    packages=find_packages()
)