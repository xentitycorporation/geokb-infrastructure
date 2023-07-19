<?php

$wgLogo = "https://scedc.caltech.edu/graphics/body/logo-usgs.png";
$wgShowExceptionDetails = true;
$wgSitename = 'GeoScience KnowledgeBase';
// disable language selection
$wgHiddenPrefs[] = 'language';
// if you want to disable variants as well
$wgHiddenPrefs[] = 'variant';
$wgHiddenPrefs[] = 'noconvertlink';
$wgLanguageCode = 'en';
$wgGroupPermissions['*']['edit'] = false;
$wgGroupPermissions['sysop']['edit']=true;
$wgGroupPermissions['sysop']['createeditmovepage'] = true;
$wgGroupPermissions['sysop']['editpage'] = true;
$wgGroupPermissions['sysop']['highvolume'] = true;

wfLoadSkin( 'Timeless' );
$wgDefaultSkin = 'Timeless';
wfLoadExtension( 'OAuth' );
$wgRestAPIAdditionalRouteFiles[] = "/var/www/public_html/OAuth/experimentalRoutes.json";

$wgWBRepoSettings['statementSections'] = [
    'item' => [
        'statements' => null,
        'identifiers' => [
            'type' => 'dataType',
            'dataTypes' => [ 'external-id' ],
        ],
    ],
];