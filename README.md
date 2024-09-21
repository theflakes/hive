# Hive
Low to mid interaction network honeypot.  

This is a modular network honeypot that can run any number of profiles mimiking various server services.  

Configuration is in Json and logging is in Json as well.  

### Requirements
```bash
sudo pip3 install python-nmap
# on ubuntu you may need to use apt to install python-nmap
sudo apt install python-nmap
sudo pip3 install netifaces
sudo pip3 install ipaddress
sudo pip3 install ipcalc
```

### Configuration
You can rename the default field names in the field_names part of the Json config.  

Each honey / listener points to a logger and each logger points to a handler.  
```json
{
	"reverse_dns": true, # Do a reverse lookup on any IP touching Hive
	"l2_attribution": false, # Run nmap against IP that touched Hive to attempt Mac retrieval
	"field_names": {
		"data_type": {
			"name": "data_type",
			"default": "Honey"
		},
		"default_gateway": {
			"name": "default_gateway",
			"default": null
		},
		"device_name": {
			"name": "device_name",
			"default": null
		},
		"dst_ip": {
			"name": "dst_ip",
			"default": null
		},
		"dst_port": {
			"name": "dst_port",
			"default": null
		},
		"hostname": {
			"name": "hostname",
			"default": null
		},
		"interface_name": {
			"name": "interface_name",
			"default": null
		},
		"ip_proto": {
			"name": "ip_proto",
			"default": null
		},
		"message": {
			"name": "message",
			"default": null
		},
		"src_ip": {
			"name": "src_ip",
			"default": null
		},
		"src_mac": {
			"name": "src_mac",
			"default": null
		},
		"src_port": {
			"name": "src_port",
			"default": null
		},
		"subnet_mask": {
			"name": "subnet_mask",
			"default": null
		},
		"src_vendor": {
			"name": "src_vendor",
			"default": null
		},
		"timestamp": {
			"name": "timestamp",
			"default": null
		}
	},
	"ll_mcast": [ # Ignore Link Local Multicast traffic on these protos and ports
		{
			"protocol": "tcp",
			"ports": []
		},
		{
			"protocol": "udp",
			"ports": [137, 138]
		}
	],
	"timeout": 1,
	"honey": [ # Services to mimick
		{
			"config": "./listeners/smb.json",
			"logger": "smb" # entry under loggers to use for this honey trap
		},
		{
			"config": "./listeners/rdp.json",
			"logger": "rdp"
		},
		{
			"config": "./listeners/wsman.json",
			"logger": "wsman"
		}
	],
	"default_logger": "root",
	"logging": {
		"version": 1,
		"formatters": {
			"standard": {
				"format": "%(message)s"
			}
		},
		"handlers": { # configuration for each log file
			"error": {
				"level": "ERROR",
				"formatter": "standard",
				"class": "logging.handlers.RotatingFileHandler",
				"filename": "error.log",
				"mode": "a",
				"maxBytes": 10485760,
				"backupCount": 5
			},
			"basic": {
				"level": "DEBUG",
				"formatter": "standard",
				"class": "logging.StreamHandler"
			},
			"smb": {
				"level": "INFO",
				"formatter": "standard",
				"class": "logging.handlers.RotatingFileHandler",
				"filename": "smb.log",
				"mode": "a",
				"maxBytes": 10485760,
				"backupCount": 5
			},
			"rdp": {
				"level": "INFO",
				"formatter": "standard",
				"class": "logging.handlers.RotatingFileHandler",
				"filename": "rdp.log",
				"mode": "a",
				"maxBytes": 10485760,
				"backupCount": 5
			},
			"wsman": {
				"level": "INFO",
				"formatter": "standard",
				"class": "logging.handlers.RotatingFileHandler",
				"filename": "wsman.log",
				"mode": "a",
				"maxBytes": 10485760,
				"backupCount": 5
			}
		},
		"loggers": {
			"root": {
				"handlers": ["basic"],
				"level": "INFO",
				"propagate": true
			},
			"smb": { # per honey logging file
				"handlers": ["smb"], # above handler for the log file
				"level": "INFO",
				"propagate": true
			},
			"rdp": {
				"handlers": ["rdp"],
				"level": "INFO",
				"propagate": true
			},
			"wsman": {
				"handlers": ["wsman"],
				"level": "INFO",
				"propagate": true
			}
		}
	}
}
```
