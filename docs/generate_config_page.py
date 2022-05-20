# This will generate configuration.md page from `settings.yaml` in sec_certs.configuration file

from sec_certs.config import configuration


def main():
    cfg = configuration.config

    with open("./configuration.md", "w") as handle:
        handle.write("# Configuration\n\n")
        handle.write(
            "The configuration is stored in yaml file `settings.yaml` at `sec_certs.config`. These are the supported options, descriptions and default values.\n\n"
        )
        for key in cfg.__dict__:
            handle.write(f"`{key}`\n\n- Description: {cfg.get_desription(key)}\n")
            handle.write(f"- Default value: `{cfg.__getattribute__(key)}`\n\n")


if __name__ == "__main__":
    main()
