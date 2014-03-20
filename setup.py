from setuptools import setup

version = "0.1"

setup(
    version=version,
    description="A plugin for mr.awsome providing integration with Amazon EC2.",
    name="mr.awsome.ec2",
    author='Florian Schulze',
    author_email='florian.schulze@gmx.net',
    url='http://github.com/fschulze/mr.awsome.ec2',
    include_package_data=True,
    zip_safe=False,
    packages=['mr'],
    namespace_packages=['mr'],
    install_requires=[
        'setuptools',
        'mr.awsome',
        'boto >= 2.0'
    ],
    setup_requires=[
        'setuptools-git'],
    entry_points="""
        [mr.awsome.plugins]
        ec2 = mr.awsome.ec2:plugin
    """)
