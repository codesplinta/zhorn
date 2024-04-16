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
  
  const { getInstance, destroy: destroyTracker } = initializeNavigatorMetricsTracker(
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