[![Generic badge](https://img.shields.io/badge/PrefumeJS-yes-gold.svg)](https://shields.io/) [![Generic badge](https://img.shields.io/badge/URISanity-yes-brown.svg)](https://shields.io/) ![@isocroft](https://img.shields.io/badge/@isocroft-CodeSplinta-blue) [![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com) [![Made in Nigeria](https://img.shields.io/badge/made%20in-nigeria-008751.svg?style=flat-square)](https://github.com/acekyd/made-in-nigeria)

# zhorn
realtime page bot detection, XSS detection, tampering detection + performance analytics tracker for the web

## Installation
>Install using `npm`

```bash
   npm install zhorn
```

>Or install using `yarn`

```bash
   yarn add zhorn
```

## Getting Started
You nee to add the `<meta>` tag (as specified below) to enable **Trusted Types** from the frontend or enable from the backend using [CSP Response Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP).

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
  ],
  (URISanity, payload) => {
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
  return event.returnValue = 'Are you sure you want to exit?';
});
```

## License

Apache 2.0 License
