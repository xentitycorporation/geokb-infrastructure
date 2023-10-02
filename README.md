# geokb-infrastructure
Various infrastructure use for wikibase services
# usgs-mrdata-wikidata

### Wikibase Setup on local computer

> Note: Using steps found in [https://www.mediawiki.org/wiki/Wikibase/Docker](https://www.mediawiki.org/wiki/Wikibase/Docker)

* Install docker and docker-compose if needed
* `mkdir <folder>`
* `cd <folder>`
* copy the `docker-compose.yml`, `jobrunner-entrypoint.sh` and `template.env` files into folder (renaming `template.env` to `.env`) from the [wikibase repo](https://github.com/wmde/wikibase-release-pipeline/tree/aef067b4daf4c3d408581d5ffba503a8bf842f2f/example)
* Change passwords for `MW_ADMIN_PASS` and `DB_PASS` in the `.env` file. Also change `MW_WG_ENABLE_UPLOADS=true`.
* Save changes and run command `docker-compose up -d`
* Use command  `docker ps` to ensure that the containers have started

You should see the webpage for the composed containers in localhost
Localhost URL: http://localhost/wiki/Main_Page

Afterwards installed WikibaseIntegrator for python found in [https://www.mediawiki.org/wiki/Wikibase/Importing](https://www.mediawiki.org/wiki/Wikibase/Importing)
to try and insert triples, although other extensions could have been used.

To start a fresh wikibase instance, the volumes need to be removed as well since they are what is caching the data. This can be done by running the command `docker-compose -f docker-compose.yml down --volumes`

### wikibase setup with extras

* copy the `docker-compose.yml`, `docker-compose.extra.yml`, `jobrunner-entrypoint.sh`, `template.env`, `extra-install.sh` files into folder (renaming `template.env` to `.env`) from the [wikibase repo](https://github.com/wmde/wikibase-release-pipeline/tree/aef067b4daf4c3d408581d5ffba503a8bf842f2f/example)
* Change passwords for `MW_ADMIN_PASS` and `DB_PASS` in the `.env` file. Also change `MW_WG_ENABLE_UPLOADS=true`.
* Save changes and run command `docker-compose -f docker-compose.yml -f docker-compose.extra.yml up -d`
* Use command  `docker ps` to ensure that the containers have started

This will create 9 docker containers rather than the 3 in the minimal install

To start a fresh wikibase instance with the extra containers, the volumes need to be removed as well since they are what is caching the data. This can be done by running the command `docker-compose -f docker-compose.yml -f docker-compose.extra.yml down --volumes`

### Pywikibot

* To create a wikibot:
- go to url [http://localhost/wiki/Main_Page](http://localhost/wiki/Main_Page) after docker instance has been run
- on the left side select "Special pages"
- under Users and rights select "Bot passwords"
- log in with the Admin credentials that was set up within the docker-compose.yml file
- create a new bot (select all the option checkboxes for now) and save the password provided for future use


* required installs:
    - `pip install -U setuptools`
    - `pip install pywikibot`
    - `pip install wikitextparser`

    It is possible that the path was not added to the environment. If that is the case, a warning such as this will pop up:
    ```
        WARNING: The script pwb.exe is installed in 'your/path/to/local-packages/Python310/Scripts' which is not on PATH.
        Consider adding this directory to PATH or, if you prefer to suppress this warning, use --no-warn-script-location.
    ```

    You can add the path by running `export PATH=$PATH:/some/new/path` 
        Note: If you are on Windows, instructions to add the path can be found [here](https://learn.microsoft.com/en-us/previous-versions/office/developer/sharepoint-2010/ee537574(v=office.14))

    you can test to see if pywikibot is working by running the command `pwb`

#### To add data to the GeoKB

* create `<family-filename>` family using command `pwb generate_family_file`
    - set url to `https://wiki.demo5280.com` and a desired name for family
    - add the following code to your familyfile i.e. `<family-filename>_family.py`
    ```
        def default_globe(self, code) -> str:
        """Default globe for Coordinate datatype."""
        return 'earth'

    def globes(self, code):
        """Supported globes for Coordinate datatype."""
        return {
            'earth': 'http://www.wikidata.org/entity/Q2'
        }
    ```

* ensuring that you are in the same directory as where you generated the family file, create user config and password files with command `pwb generate_user_files`
    - selected yes on adding a BotPassword
    - used same name for bot when it was created within the wikibase instance
    - add password provided by wikibase instance
    - It will prompt on whether to add additional options in the user-config.py file. They're not necessary to set up for the connection to the wikibase to be established.

* change user-config file to read only by running `chmod 0444 user-config.py`
    (`Set-ItemProperty -Path ./user-config.py -Name IsReadOnly -Value $true` for Windows)

* run `pwb login`

* Now the connection to the wikibase instance should work and scripts with Pywikibot will work.

#### For Local Testing

* create `<family-filename>` family using command `pwb generate_family_file`
    - set url to `http://localhost:80` and a desired name for family
    - add the following code to your familyfile i.e. `<family-filename>_family.py`
    ```
        def default_globe(self, code) -> str:
        """Default globe for Coordinate datatype."""
        return 'earth'

    def globes(self, code):
        """Supported globes for Coordinate datatype."""
        return {
            'earth': 'http://www.wikidata.org/entity/Q2'
        }
    ```

* ensuring that you are in the same directory as where you generated the family file, create user config and password files with command `pwb generate_user_files`
    - selected yes on adding a BotPassword
    - used same name for bot when it was created within the wikibase instance
    - add password provided by wikibase instance
    - It will prompt on whether to add additional options in the user-config.py file. They're not necessary to set up for the connection to the wikibase to be established.

* change user-config file to read only by running `chmod 0444 user-config.py`
    (`Set-ItemProperty -Path ./user-config.py -Name IsReadOnly -Value $true` for Windows)

* run `pwb login`

* Now the connection to the wikibase instance should work and scripts with Pywikibot will work.

To populate the wikibase with data
* cd `scripts/`
* run `python prereq_setup.py`
* run `python GeoKBBot.py`

This will run a specific conf file that the filepath within GeoKBBot.py is pointing to.
Alternatively, there is an example Jupyter Notebook within the `examples/mrds_example` folder that shows how to load data based on different conf files.

### Troubleshooting

It might be possible that the bot won't let you login using `pwb login`. If that's the case

* Check to make sure the `user-config.py`, `user-password.py` and `families/` are on the same level as the script. If you do need to move the files into the right location, make sure to set read only permissions again to the `user-config.py`.

Steps taken to get quickstatements running

* Created a new oauth consumer and saved the key and secret from result. This was because the callback URL was not correct when the wikibase was first created and there is no way to set a different one using the GUI or wikibase API. To create a new oauth consumer, you can use the php script found in the main wikibase instance (in my case it was named wikibase-1). the command for it is
```bash
php /var/www/html/extensions/OAuth/maintenance/createOAuthConsumer.php \
    --approve \
    --callbackUrl $QS_PUBLIC_SCHEME_HOST_AND_PORT/api.php \
    --callbackIsPrefix true \
    --user $MW_ADMIN_NAME \
    --name <NEW_NAME> \
    --description QuickStatements \
    --version 1.0.1 \
    --grants createeditmovepage \
    --grants editpage \
    --grants highvolume \
    --jsonOnSuccess
```
(The command was found [here](https://www.mediawiki.org/wiki/Wikibase/Suite#QuickStatements))

The response will look like this 

```json
{"created":true,"id":1,"name":"QuickStatements","key":"<OAUTH_KEY>","secret":"<OAUTH_SECRET>","approved":1}
```

To access the docker container using the CLI, use `docker ps` to find the name of the main wikibase container, then run `docker exec -it <CONTAINER_NAME> /bin/bash`

* manually pass in `oauth.ini` file with the oauth key and secret values as well as the `qs-config.json` (renamed as `config.json`) with the correct configuration paths. The way it was passed in with the current set up was through the .yml file. Find the `quickstatements` service and add the following lines to the volumes array
```yml
- ./qs-config.json:/var/www/html/quickstatements/public_html/config.json
- ./oauth.ini:/quickstatements/data/oauth.ini
```

