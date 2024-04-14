// Type definitions for zhorn v0.0.2
// Project: https://github.com/codesplinta/zhorn

declare global {
    interface WindowEventMap {
        'agentmetricavailable': CustomEvent<typeof agentMetricDetails>;
        'agentbotactivity': CustomEvent<typeof agentBotActivityDetails>;
    }
    interface DocumentEventMap {
        'beforeinclude': CustomEvent<typeof agentBeforeIncludeDetails>;
        'beforerequest': CustomEvent<typeof agentBeforeRequestDetails>
    }
}

declare const agentBeforeRequestDetails: {
    /**
	 The URL endpoint for the async request.
	*/
    endpoint: string,
    /**
	 The HTTP method name for the async request.
	*/
    method: "GET" | "PUT" | "DELETE" | "HEAD" | "PATCH" | "POST",
    /**
	 The DOM sink or Browser API that initiated the async request.
	*/
    sink: "XMLHttpRequest.send" | "HTMLImageElement.src" | "Navigator.sendBeacon" | "fetch",
    /**
     The request payload
     */
    data: Record<string, unknown> | null
};

declare const agentBeforeIncludeDetails: {
    /**
	 The markup snippet to be included.
	*/
    endpoint: string,
    /**
	 The HTTP method name for the async request.
	*/
    method: "GET",
    /**
	 The DOM sink or Browser API that initiated the markup include.
	*/
    sink: "HTMLElement.setAttribute",
    /**
     
     */
    data: null
}

declare const agentMetricDetails: {
	/**
	 The mertric name.
	*/
	readonly metric: string;

	/**
	  The payload of the metric measurement
	*/
	readonly payload: Record<string, unknown> | number | string;
};

declare const agentBotActivityDetails: {
    /**
	 The flag that shows if all bot tests matched.
	*/
	readonly captured: boolean;

	/**
	  The cases for each bot test.
	*/
	readonly cases: Record<string, boolean>;
} 

export type AgentMetricDetails = typeof agentMetricDetails;

export type AgentBotActivityDetails = typeof agentBotActivityDetails;

export type AgentBeforeRequestDetails = typeof agentBeforeRequestDetails;

export type AgentBeforeIncludeDetails = typeof agentBeforeIncludeDetails;

declare module 'zhorn' {
    type ResultObject<O> = {
       getInstance: () => O;
       destroy: Function;
    };
    export function initializeBotDetector(botCheckTimeout?: number): ResultObject<Error>;
    export function initializeXSSDetector(urlWhiteList: string[], urlsCheckCallback: (URISanity: import('urisanity').URISanityAPI, payload: AgentBeforeRequestDetails) => void): ResultObject<Error>;
    export function initializeNavigatorMetricsTracker(maxMeasureTime?: number, resourceTiming?: boolean, elementTiming?: boolean): ResultObject<import('perfume.js').Perfume>;
}