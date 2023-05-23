Testing Framework
-----------------

As NAPALM consists of multiple drivers and all of them have to provide similar functionality, we have developed a testing framework to provide a consistent test suite for all the drivers.

Features
________

The testing framework has the following features:

1. Same tests across all vendors. Tests defined in ``napalm.base/test/getters.py`` are shared across all drivers.
2. Multiple test cases per test.
3. Target of the test can be configured with environmental variables.
4. Expected output is compared against the actual output of the test result.
5. NotImplemented methods are skipped automatically.

Using the testing framework
___________________________

To use the testing framework you have to implement two files in addition to the mocked data:

- ``test/unit/test_getters.py`` - Generic file with the same content as this file `test_getters.py`_
- ``test/unit/conftest.py`` - Code specific to each driver with instructions on how to fake the driver. For example, `conftest.py`_

Multiple test cases
^^^^^^^^^^^^^^^^^^^

To create test cases for your driver you have to create a folder named ``test/unit/mocked_data/$name_of_test_function/$name_of_test_case``. For example:

- ``test/unit/mocked_data/test_get_bgp_neighbors/no_peers/``
- ``test/unit/mocked_data/test_get_bgp_neighbors/lots_of_peers/``

Each folder will have to contain it's own mocked data and expected result.

Target
^^^^^^

By default, the tests are going to be run against mocked data but you can change that behavior with the following environmental variables:

* ``NAPALM_TEST_MOCK`` - 1 (default) for mocked data and 0 for connecting to a device.
* ``NAPALM_HOSTNAME``
* ``NAPALM_USERNAME``
* ``NAPALM_PASSWORD``
* ``NAPALM_OPTIONAL_ARGS``

Mocking the ``open`` method
^^^^^^^^^^^^^^^^^^^^^^^^^^^

To mock data needed to connect to the device, ie, needed by the ``open`` method, just put the data in the folder ``test/unit/mocked_data/``

Examples
________

Multiple test cases::

    (napalm) ➜  napalm-eos git:(test_framework) ✗ ls test/unit/mocked_data/test_get_bgp_neighbors
    lots_of_peers no_peers      normal
    (napalm) ➜  napalm-eos git:(test_framework) ✗ py.test test/unit/test_getters.py::TestGetter::test_get_bgp_neighbors
    ...
    test/unit/test_getters.py::TestGetter::test_get_bgp_neighbors[lots_of_peers] <- ../napalm/napalm.base/test/getters.py PASSED
    test/unit/test_getters.py::TestGetter::test_get_bgp_neighbors[no_peers] <- ../napalm/napalm.base/test/getters.py PASSED
    test/unit/test_getters.py::TestGetter::test_get_bgp_neighbors[normal] <- ../napalm/napalm.base/test/getters.py PASSED

Missing test cases::

    (napalm) ➜  napalm-eos git:(test_framework) ✗ ls test/unit/mocked_data/test_get_bgp_neighbors
    ls: test/unit/mocked_data/test_get_bgp_neighbors: No such file or directory
    (napalm) ➜  napalm-eos git:(test_framework) ✗ py.test test/unit/test_getters.py::TestGetter::test_get_bgp_neighbors
    ...
    test/unit/test_getters.py::TestGetter::test_get_bgp_neighbors[no_test_case_found] <- ../napalm/napalm.base/test/getters.py FAILED

    ========================================================= FAILURES ==========================================================
    ___________________________________ TestGetter.test_get_bgp_neighbors[no_test_case_found] ___________________________________

    cls = <test_getters.TestGetter instance at 0x10ed5eb90>, test_case = 'no_test_case_found'

        @functools.wraps(func)
        def wrapper(cls, test_case):
            cls.device.device.current_test = func.__name__
            cls.device.device.current_test_case = test_case

            try:
                # This is an ugly, ugly, ugly hack because some python objects don't load
                # as expected. For example, dicts where integers are strings
                result = json.loads(json.dumps(func(cls)))
            except IOError:
                if test_case == "no_test_case_found":
    >               pytest.fail("No test case for '{}' found".format(func.__name__))
    E               Failed: No test case for 'test_get_bgp_neighbors' found

    ../napalm/napalm.base/test/getters.py:64: Failed
    ================================================= 1 failed in 0.12 seconds ==================================================

Method not implemented::

    (napalm) ➜  napalm-eos git:(test_framework) ✗ py.test test/unit/test_getters.py::TestGetter::test_get_probes_config
    ...
    test/unit/test_getters.py::TestGetter::test_get_probes_config[no_test_case_found] <- ../napalm/napalm.base/test/getters.py SKIPPED

    ================================================= 1 skipped in 0.09 seconds =================================================

Testing Matrix
--------------

NAPALM leverages [Github Actions](https://docs.github.com/en/actions) to test and lint code on commits and pull requests.
If you want to test prior to opening a pull request, you can use [nektos/act](https://github.com/nektos/act) and Docker to locally run the tests

.. code-block:: console

    $ act -j std_tests
    [build/std_tests-4] 🚀  Start image=catthehacker/ubuntu:act-latest
    [build/std_tests-3] 🚀  Start image=catthehacker/ubuntu:act-latest
    [build/std_tests-1] 🚀  Start image=catthehacker/ubuntu:act-latest
    [build/std_tests-2] 🚀  Start image=catthehacker/ubuntu:act-latest
    [build/std_tests-5] 🚀  Start image=catthehacker/ubuntu:act-latest
    [build/std_tests-4]   🐳  docker pull image=catthehacker/ubuntu:act-latest platform= username= forcePull=true
    [build/std_tests-1]   🐳  docker pull image=catthehacker/ubuntu:act-latest platform= username= forcePull=true
    [build/std_tests-3]   🐳  docker pull image=catthehacker/ubuntu:act-latest platform= username= forcePull=true
    [build/std_tests-5]   🐳  docker pull image=catthehacker/ubuntu:act-latest platform= username= forcePull=true
    [build/std_tests-2]   🐳  docker pull image=catthehacker/ubuntu:act-latest platform= username= forcePull=true

    ...

    | ---------------------------------------------------------------------
    | TOTAL                                    9258   1836    80%
    |
    | ================= 619 passed, 80 skipped, 3 warnings in 19.97s =================
    [build/std_tests-5]   ✅  Success - Main Run Tests
    [build/std_tests-5] ⭐ Run Post Setup Python 3.11
    [build/std_tests-5]   🐳  docker exec cmd=[node /var/run/act/actions/actions-setup-python@v2/dist/cache-save/index.js] user= workdir=
    [build/std_tests-5]   ✅  Success - Post Setup Python 3.11
    [build/std_tests-5] 🏁  Job succeeded


.. _`test_getters.py`: https://github.com/napalm-automation/napalm-eos/blob/a2fc2cf6a98b0851efe4cba907086191b8f1df02/test/unit/test_getters.py
.. _`conftest.py`: https://github.com/napalm-automation/napalm-eos/blob/a2fc2cf6a98b0851efe4cba907086191b8f1df02/test/unit/conftest.py
