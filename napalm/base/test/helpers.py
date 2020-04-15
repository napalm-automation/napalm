"""Several methods to help with the tests."""


def test_model(model, data):
    """Return if the dictionary `data` complies with the `model`."""
    same_keys = set(model.keys()) == set(data.keys())

    if not same_keys:
        print(
            "model_keys: {}\ndata_keys: {}".format(
                sorted(model.keys()), sorted(data.keys())
            )
        )

    correct_class = True
    for key, instance_class in model.items():
        correct_class = isinstance(data[key], instance_class) and correct_class
        if not correct_class:
            print(
                "key: {}\nmodel_class: {}\ndata_class: {}".format(
                    key, instance_class, data[key].__class__
                )
            )

    return correct_class and same_keys
