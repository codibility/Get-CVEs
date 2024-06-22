import os

packages_directory = os.path.dirname(__file__)
# Removing the packages folder from the path
if "packages" in packages_directory:
    main_folder = '/'.join(packages_directory.split('/')[:-1])
else:
    main_folder = packages_directory


conf_file = os.path.join(main_folder, 'cve.conf')


with open(conf_file) as f:
    init_conf: dict[str, str] = {}
    for i in f:
        if i.startswith("#") or len(i) < 2: continue
        i = i.strip().split(":")
        key = i[0].strip()
        value = i[1].strip()

        if value != "":
            if 'location' in key:
                if not os.path.isabs(value):
                    value = os.path.join(main_folder, value)
                    if not os.path.exists(value):
                        print("Invalid File path entered in: ", key, value)
                        quit()

        init_conf[key] = value

init_conf['languages'] = [x.strip().lower() for x in init_conf['languages'].replace("'", "").split(',')]
