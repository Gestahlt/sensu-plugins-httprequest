# Sensu Plugin httprequest 

## Functionality
  This plugin is intended as a versatile method to trigger HTTP(S) REST
  requests (i.e. for SMS gateways, Ticket systems and so on).

## Files
 * bin/handler-httprequest.rb

## Usage for handler-httprequest.rb
```
{ 
  "httprequest": {
    "method": "Post",
    "url": "http://my-rest-endpoint.com/path/to/api",
    "body": { 
      "body": "content",
      "dependend": "On header content type",
      "it_is": "either www-form or json"
    },
    "header": { 
      "Content-Type": "application/json",
      "default": "application/x-www-form-urlencoded",
      "other_headers": "like User-Agent and such"
    },
    "params": { 
      "this_translates": "to request parameters",
      "for_each": "key value pair"
    },
    "username": "used_for",
    "password": "basic_auth",
    "subscriptions": {
      "minimal_all_else_is_optional": {
        "url": "http://default-method-is.post"
      },
      "templated": {
        "url": "https://content-key-value-pairs.are/exclusive/with/templates,
        "body_template": "/path/to/body_template.erb",
        "header_template": "/path/to/header_template.erb",
        "params_template": "/path/to/params_template.erb"
      }
    }
  }
}
```
## Usage for template.erb
```
{ 
  "message": "#{@event['client']['name']} #{@event['check']['name']} #{@event['check']['status']}"
}
```


## Installation

[Installation and Setup](https://sensu-plugins.io/docs/installation_instructions.html)

## Notes

The configuration works also without a HTTP request definition and subscriptions only. Subscriptions are optional. 
The "main" request definition will trigger always when the handler is executed and additionally all matching subscriptions.
An alternate configuration name can be supplied with the parameter -j / --json.
Templates must conform to json format.
