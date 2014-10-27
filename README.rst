Overview
========

The ploy_ec2 plugin provides integration of `Amazon EC2`_ with `ploy`_.

.. _Amazon EC2: http://aws.amazon.com/ec2/
.. _ploy: https://github.com/ployground/


Installation
============

ploy_ec2 is best installed with easy_install, pip or with zc.recipe.egg in a buildout.


Masters
=======

To use ploy_ec2 you need an Amazon account and `AWS keys <http://docs.aws.amazon.com/general/latest/gr/getting-aws-sec-creds.html>`_.

Once you got your keys, you should put them in a secure location and reference them in your ``ploy.conf``.
Additionally you need to set the region of the master::

    [ec2-master:ec2eu]
    access-key-id = ~/.aws/ec2.id
    secret-access-key = ~/.aws/ec2.key
    region = eu-west-1

You can also set the ``AWS_ACCESS_KEY_ID`` and ``AWS_SECRET_ACCESS_KEY`` environment variables instead.

You need to define a master for each `region <http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html>`_ you want to use.


Instances
=========

Each instance has the following mandatory settings:

``image``
  The `Amazon Machine Image (AMI) <http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html>`_ that this instance will start up with.

``keypair``
  The name of the `SSH keypair <http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html>`_ to use.

``placement``
  The `availability zone <http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html>`_ in which to launch the instances.

``securitygroups``
  The name of the `Securitygroups`_ this instance should be assigned to.

The following settings are optional:

``instance_type``

``ip``

``startup_script``
  Path to a script which will be run right after creation and first start of the instance.
  This uses the `User Data <http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html>`_ feature and needs to be supported by the AMI.

``volumes``

``snapshots``

``device_map``

``delete-volumes-on-terminate``


Securitygroups
==============

``description``

``connections``
  ::

    [ec2-securitygroup:app-server]
    description = The production server
    connections =
        tcp     22      22      0.0.0.0/0
        tcp     80      80      0.0.0.0/0


Macro expansion
===============

For instances the ``ip`` and ``volumes`` options aren't copied when expanding macros.
