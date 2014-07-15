Changelog
=========

1.0b5 - Unreleased
------------------



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
