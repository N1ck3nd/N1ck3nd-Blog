---
title: 'Generate Your Own API Documentation'
date: 2024-04-25 15:50:00 +0800
categories: [Web]
tags: [api]
image:
  path: /assets/posts/2024-04-25-Generate-Your-Own-API-Documentation/thumbnail.png
  alt: 'Thumbnail image with title'
---

During a web application assessment, I was testing a web application which, like many web apps, interacted with a database system via a web API. Since the scope solely allowed for testing from a front-end perspective, I was not provided with any API documentation such as Postman or Swagger files.

With that said, to make testing APIs easier, I recently learnt a technique to generate my own API documentation when I was following along with one of [APIsec University](https://www.apisecuniversity.com/)'s excellent courses. This technique involves capturing HTTP requests by using `mitmproxy`, an HTTP proxy, and subsequently converting the captured requests into Swagger documentation by using `mitmproxy2swagger`.

## Demonstration

*In this demonstration I will be using [OWASP crAPI](https://github.com/OWASP/crAPI), an intentionally vulnerable web application, to showcase how API documentation may be generated from captured HTTP requests.*

### Installing `mitmproxy` and `mitmproxy2swagger`

Before you can start intercepting and capturing HTTP requests, you need to install [`mitmproxy`](https://mitmproxy.org/). On macOS, provided that Homebrew is installed, you may run the following command:

```bash
brew install mitmproxy
```

*For other platforms, please refer to the [`mitmproxy` installation documentation](https://docs.mitmproxy.org/stable/overview-installation/).*

To install [`mitmproxy2swagger`](https://github.com/alufers/mitmproxy2swagger) using pipx, execute the following command:

```bash
pipx install mitmproxy2swagger
```

After the installations have finished, execute the following command to start `mitmweb`:

```bash
mitmweb
[13:17:08.004] HTTP(S) proxy listening at *:8080.
[13:17:08.005] Web server listening at http://127.0.0.1:8081/
[13:17:20.626][127.0.0.1:51917] client connect
```

Configure your browser or browser extension, such as [FoxyProxy](https://github.com/foxyproxy/browser-extension), to redirect HTTP traffic to port `8080` on the localhost, and visit <https://mitm.it/> to install the `mitmproxy CA certificate` by following instructions for your specific platform.

### Capturing data with  `mitmproxy`

After everything has been configured correctly, it is time to start browsing and interacting with the target application just like how a normal user of the application would. By browsing the application and performing actions, such as creating a new user account or changing a user's profile, more requests are accumulated by `mitmproxy`.

When you are done clicking through the application and have captured all the HTTP requests, it is time to visit <http://localhost:8081/#/flows> and save the captured data to your local computer.

<img src="/assets/posts/2024-04-25-Generate-Your-Own-API-Documentation/mitmweb.png" alt="mitmweb Interface" width="700"/>

### Creating documentation with `mitmproxy2swagger`

Now that the `mitmproxy` flow file has been saved, it can be converted into an OpenAPI specification file by running `mitmproxy2swagger` with various parameters. The command below takes the `flows` flow file, filters out any superfluous HTTP requests, and outputs data to `spec.yml`.  

```bash
mitmproxy2swagger -i flows -o spec.yml -p http://crapi:8888 -f flow

No existing swagger file found. Creating new one.
[                              ] 1.2%[warn] flow without response: https://www.google.com/complete/search?client=chrome-omni&gs_ri=chrome-ext-ansg&xssi=t&q=[...SNIP...]]
[▌▌▌▌▌▌▌▌▌                     ] 31.6%[warn] flow without response: https://www.google.com/maps/embed?origin=mfe&pb=!1m2!2m1!1s31.888888,-92.111176
[▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌] 100.0%Done!
```

Before documentation can be generated, in the `spec.yml` file,  remove the `ignore:` prefix for endpoints which you want to include in the API documentation.

```yaml
openapi: 3.0.0
info:
  title: flows Mitmproxy2Swagger
  version: 1.0.0
servers:
- url: http://crapi:8888
  description: The default server
paths: {}
x-path-templates:
# Remove the ignore: prefix to generate an endpoint with its URL
# Lines that are closer to the top take precedence, the matching is greedy
- ignore:/
- /community/api/v2/community/posts
- /community/api/v2/community/posts/recent
- /community/api/v2/community/posts/tEMixSh28yNHYrsDPbzxfh
- /community/api/v2/community/posts/tEMixSh28yNHYrsDPbzxfh/comment
- /community/api/v2/coupon/validate-coupon
- ignore:/favicon.ico
- /identity/api/auth/forget-password
- /identity/api/auth/login
- /identity/api/auth/signup
- /identity/api/auth/v3/check-otp
- /identity/api/v2/user/change-email
- /identity/api/v2/user/dashboard
- /identity/api/v2/user/pictures
- /identity/api/v2/user/verify-email-token
- /identity/api/v2/user/videos
- /identity/api/v2/user/videos/{id}
- /identity/api/v2/user/videos/38
- /identity/api/v2/user/videos/convert_video
- /identity/api/v2/vehicle/706b8ceb-8af4-4275-95d3-2c9221cccf51/location
- /identity/api/v2/vehicle/add_vehicle
- /identity/api/v2/vehicle/vehicles
- ignore:/images/bmw-5.jpg
- ignore:/images/mgmotor-hectorplus.jpg
- ignore:/images/seat.svg
- ignore:/images/wheel.svg
- ignore:/static/css/2.0f314ae8.chunk.css
- ignore:/static/css/main.c0e8c94c.chunk.css
- ignore:/static/js/2.ecbd5ce0.chunk.js
- ignore:/static/js/main.ccf90738.chunk.js
- ignore:/static/media/default_profile_pic.24d66af2.png
- /workshop/api/mechanic
- /workshop/api/mechanic/
- /workshop/api/merchant/contact_mechanic
- /workshop/api/shop/orders
- /workshop/api/shop/orders/{id}
- /workshop/api/shop/orders/12
- /workshop/api/shop/orders/all
- /workshop/api/shop/orders/return_order
- /workshop/api/shop/products
- /workshop/api/shop/return_qr_code
```

After fine-tuning the `spec.yml` file, re-run the previous command to generate your own API documentation. The `spec.yml` file will now be turned into API documentation.

```bash
mitmproxy2swagger -i flows -o spec.yml -p http://crapi:8888 -f flow

[                              ] 1.2%[warn] flow without response: https://www.google.com/complete/search?client=chrome-omni&gs_ri=chrome-ext-ansg&xssi=t&q=[...SNIP...]]
[▌▌▌▌▌▌▌▌▌                     ] 31.6%[warn] flow without response: https://www.google.com/maps/embed?origin=mfe&pb=!1m2!2m1!1s31.888888,-92.111176
[▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌▌] 100.0%Done!
```

Finally, take the `spec.yml` file and import the contents into SwaggerEditor or Postman to view requests, request methods, request parameters, and responses. From here, you can begin to develop a deeper understanding of how a specific API works and start identifying potential vulnerabilities and misconfigurations.

<img src="/assets/posts/2024-04-25-Generate-Your-Own-API-Documentation/swaggereditor.png" alt="SwaggerEditor" width="1000"/>
