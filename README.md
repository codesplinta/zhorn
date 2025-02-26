[![Generic badge](https://img.shields.io/badge/PrefumeJS-yes-gold.svg)](https://shields.io/) [![Generic badge](https://img.shields.io/badge/URISanity-yes-brown.svg)](https://shields.io/) ![@isocroft](https://img.shields.io/badge/@isocroft-CodeSplinta-blue) [![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)  [![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)](https://standardjs.com) [![Made in Nigeria](https://img.shields.io/badge/made%20in-nigeria-008751.svg?style=flat-square)](https://github.com/acekyd/made-in-nigeria)

# zhorn
realtime page bot detection, XSS detection and performance analytics tracker for the web

## Installation
>Install using `npm`

```bash
   npm install zhorn
```

>Or install using `yarn`

```bash
   yarn add zhorn
```

### Browser

> Using a `script` tag directly inside a web page

```html
<script type="text/javascript" src="https://unpkg.com/browse/zhorn@0.0.3/dist/zhorn.umd.js" crossorigin="anonymous"></script>
```

### CommonJS

```js
const { initializeBotDetector } = require('zhorn')
```

## Getting Started
You need to add the `<meta>` tag (as specified below) to enable **Trusted Types** from the frontend or enable from the backend using [CSP Response Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP).

```html
<!-- CSP Whitelist ONLY -->
<meta http-equiv="Content-Security-Policy" content="default-src 'self' blob:; script-src https://code.tidio.co http://code.tidio.co https://widget-v4.tidiochat.com 'self' 'sha256-BvzNrSckoP+jHUq6lGFL71O00yDzkfzBQFCqOQH3Tuo=' 'strict-dynamic'; style-src 'self' https://fonts.googleapis.com https://maxst.icons8.com; img-src 'self' https://cdnjs.cloudflare.com https://tidio-images-messenger.s3.amazonaws.com data:; media-src https://widget-v4.tidiochat.com; font-src 'self' https://widget-v4.tidiochat.com https://fonts.gstatic.com https://maxst.icons8.com; connect-src 'self' https://gatedapi.mysaasapp.com; worker-src 'self';" />

<!-- OR: CSP Trusted Types Config ONLY -->

<meta http-equiv="Content-Security-Policy" content="require-trusted-types-for 'script'; trusted-types dompurify zhornpuritan">

<!-- OR: Both -->

<meta http-equiv="Content-Security-Policy" content="default-src 'self' blob:; script-src https://code.tidio.co http://code.tidio.co https://widget-v4.tidiochat.com 'self' 'sha256-BvzNrSckoP+jHUq6lGFL71O00yDzkfzBQFCqOQH3Tuo=' 'strict-dynamic'; style-src 'self' https://fonts.googleapis.com https://maxst.icons8.com; img-src 'self' https://cdnjs.cloudflare.com https://tidio-images-messenger.s3.amazonaws.com data:; media-src https://widget-v4.tidiochat.com; font-src 'self' https://widget-v4.tidiochat.com https://fonts.gstatic.com https://maxst.icons8.com; connect-src 'self' https://gatedapi.mysaasapp.com; worker-src 'self'; require-trusted-types-for 'script'; trusted-types dompurify zhornpuritan" />
```

Afterwards, you can import the project and begin the further setup

```javascript
import {
  initializeBotDetector,
  initializeXSSDetector,
  initializeNavigatorMetricsTracker
} from "zhorn";

const { destroy: destroyBotDetector } = initializeBotDetector(
  1500 /* :botCheckTimeout: */
)

const { destroy: destroyXSSDetector } = initializeXSSDetector(
  /* @HINT: You need to extract the whilelisted URLs from CSP white list */
  /* @HINT: The CSP whitelist from the `<meta>` tag or the CSP Response Headers */
  [
    "https://code.tidio.co",
    "http://code.tidio.co",
    "https://widget-v4.tidiochat.com",
    "https://fonts.googleapis.com",
    "https://maxst.icons8.com",
    "https://cdnjs.cloudflare.com",
    "https://tidio-images-messenger.s3.amazonaws.com",
    "https://fonts.gstatic.com",
    "https://gatedapi.mysaasapp.com",
    "https://apis.google-analytics.com"
  ],
  (URISanity, payload) => {
    const { origin } = new URL(payload.endpoint);

    /* @HINT: Check that only the request params we need are attached */
    /* @HINT: Any other extra params should not be allowed */
    if (origin.includes('.google-analytics.')) {
      if (URISanity.checkParamsOverWhiteList(
        payload.endpoint,
        ['tid', 'cid'],
        payload.data
      )) {
        return;
      }
      throw new Error("URL query string not valid")
    }
  }
);

const { getInstance, destroy: destroyTracker } =  initializeNavigatorMetricsTracker(
  10000 /* :maxMeasureTime: */
)

const tracker = getInstance();

window.addEventListener('beforeunload', function onBeforeUnLoad (event) {
  /* @HINT: Free up memory */
  destroyBotDetector()
  destroyXSSDetector()
  destroyTracker()

  /* @HINT: Preserve the BF Cache */
  /* @CHECK: https://web.dev/articles/bfcache */
  window.removeEventListener('beforeunload', onBeforeUnLoad);

  event.preventDefault();
  event.returnValue = undefined;
  return;
});
```

Or you could create a ReactJS hook: **useZhornTracker()**

```javascript
import { useState, useMemo } from "react";
import { useBeforePageUnload } from "react-busser";
import {
  initializeBotDetector,
  initializeXSSDetector,
  initializeNavigatorMetricsTracker
} from "zhorn";

export const useZhornTracker = () => {
   const [{ destroy: destroyBotDetector }] = useState(() => initializeBotDetector(
     1500 /* :botCheckTimeout: */
   ));
   const [{ getInstance, destroy: destroyTracker }] = useState(() => initializeNavigatorMetricsTracker(
     10000 /* :maxMeasureTime: */
   ));
   const [{ destroy: destroyXSSDetector }] = useState(() => initializeXSSDetector(
     /* @HINT: You need to extract the whilelisted URLs from CSP white list */
     /* @HINT: The CSP whitelist from the `<meta>` tag or the CSP Response Headers */
     [
       "https://code.tidio.co",
       "http://code.tidio.co",
       "https://widget-v4.tidiochat.com",
       "https://fonts.googleapis.com",
       "https://maxst.icons8.com",
       "https://cdnjs.cloudflare.com",
       "https://tidio-images-messenger.s3.amazonaws.com",
       "https://fonts.gstatic.com",
       "https://gatedapi.mysaasapp.com",
       "https://apis.google-analytics.com"
     ],
     (URISanity, payload) => {
       const { origin } = new URL(payload.endpoint);
   
       /* @HINT: Check that only the request params we need are attached */
       /* @HINT: Any other extra params should not be allowed */
       if (origin.includes('.google-analytics.')) {
         if (URISanity.checkParamsOverWhiteList(
           payload.endpoint,
           ['tid', 'cid'],
           payload.data
         )) {
           return;
         }
         throw new Error("URL query string not valid")
       }
     }
   ));

   useBeforePageUnload(() => {
      const isClosed = window.closed;

      setTimeout(() => {
        if (isClosed || !window || window.closed) {
          destroyBotDetector();
          destroyTracker();
          destroyXSSDetector();
        }
      }, 0);

      return undefined;
   }, { when: true });

   return useMemo(() => getInstance(), []);
};
```

## License

Apache 2.0 License

## Browser Support

- IE 11.0+
- Edge 16.0+
- Chrome 44.0+
- Firefox 45.0+
- Safari 12.0+
- Opera 28.0+
- Samsung Internet 4.0+

## Contributing

If you wish to contribute to this project, you are very much welcome. Please, create an issue first before you proceed to create a PR (either to propose a feature or fix a bug). Make sure to clone the repo, checkout to a contribution branch and build the project before making modifications to the codebase.

Run all the following command (in order they appear) below:

```bash

$ npm run lint

$ npm run build

$ npm run test
```
