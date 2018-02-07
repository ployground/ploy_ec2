Changelog
=========

2.0.0b1 - 2018-02-07
--------------------

* Support for ploy 2.0.0.
  [fschulze]

* Support yet another ssh key output format from console output of instance.
  [fschulze]


1.2.0 - 2015-09-03
------------------

* Check status of volume to give helpful error message if it's still attached.
  [fschulze]

* Allow volume definition via ``ec2-volume`` sections.
  [fschulze]

* Fix support of console output for the ``ploy debug -c`` command.
  [fschulze]

* Reuse init_ssh_key from ploy.plain to get way more options and error checking.
  [fschulze]


1.1.1 - 2015-01-22
------------------

* Only set device_map if it's in the config, the previous ``None`` default
  didn't always work.
  [fschulze]

* Fixed console output availability test for the status command.
  [fschulze]

* Better error message if fingerprint isn't in console output.
  [fschulze]

* There can be multiple instances for the same name if they were quickly started
  and stopped. Handle that case when requesting status of master.
  [fschulze]


1.1.0 - 2014-10-27
------------------

* Print status of all ec2 instances when requesting status of master.
  [fschulze]


1.0.0 - 2014-07-19
------------------

* Added documentation.
  [fschulze]


1.0b4 - 2014-07-15
------------------

* Fix confusion between instance from ploy and ec2 instance.
  [fschulze]


1.0b3 - 2014-07-08
------------------

* Moved ``snapshots`` list command here after ploy enabled it.
  [fschulze]

* Renamed mr.awsome to ploy and mr.awsome.ec2 to ploy_ec2.
  [fschulze]


1.0b2 - 2014-05-15
------------------

* Renamed ``conn`` to ``ec2_conn`` to allow reuse of ``conn`` from BaseInstance.
  [fschulze]

* Moved setuptools-git from setup.py to .travis.yml, it's only needed for
  releases and testing.
  [fschulze]


1.0b1 - 2014-03-24
------------------

* Initial release
  [fschulze]
