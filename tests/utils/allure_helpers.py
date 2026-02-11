import json

import allure


def attach_payload(payload):
    allure.attach(
        json.dumps(payload, indent=2),
        name="Input Payload",
        attachment_type=allure.attachment_type.JSON,
    )


def attach_bundle_yaml(path):
    with open(path, "r", encoding="utf-8") as file:
        content = file.read()
    allure.attach(
        content,
        name="YAML Bundle",
        attachment_type=allure.attachment_type.YAML,
    )


def attach_output(output, name="mpe Output"):
    allure.attach(output, name=name, attachment_type=allure.attachment_type.TEXT)

