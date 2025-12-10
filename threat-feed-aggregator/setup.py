from setuptools import setup, find_packages

setup(
    name='threat-feed-aggregator',
    version='0.1.0',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'Flask',
        'requests',
    ],
    entry_points={
        'console_scripts': [
            'threat-feed-aggregator=threat_feed_aggregator.app:main',
        ],
    },
)
