export namespace main {
	
	export class LogEntry {
	    // Go type: time
	    timestamp: any;
	    level: string;
	    message: string;
	    context?: Record<string, any>;
	
	    static createFrom(source: any = {}) {
	        return new LogEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.timestamp = this.convertValues(source["timestamp"], null);
	        this.level = source["level"];
	        this.message = source["message"];
	        this.context = source["context"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ProxyConfig {
	    type: string;
	    address: string;
	    port: string;
	    username: string;
	    password: string;
	    enabled: boolean;
	    headers: Record<string, string>;
	    cookies: Record<string, string>;
	
	    static createFrom(source: any = {}) {
	        return new ProxyConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.type = source["type"];
	        this.address = source["address"];
	        this.port = source["port"];
	        this.username = source["username"];
	        this.password = source["password"];
	        this.enabled = source["enabled"];
	        this.headers = source["headers"];
	        this.cookies = source["cookies"];
	    }
	}
	export class ScanOptions {
	    targets: string[];
	    scanType: string;
	    threads: number;
	    timeout: number;
	    proxy: ProxyConfig;
	    allowRedirect: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ScanOptions(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.targets = source["targets"];
	        this.scanType = source["scanType"];
	        this.threads = source["threads"];
	        this.timeout = source["timeout"];
	        this.proxy = this.convertValues(source["proxy"], ProxyConfig);
	        this.allowRedirect = source["allowRedirect"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Vulnerability {
	    id: number;
	    vulnerabilityType: string;
	    severity: string;
	    target: string;
	    url: string;
	    payload: string;
	    description: string;
	    proof: string;
	    recommendation: string;
	    responseHeaders: Record<string, string>;
	    responseContent: string;
	    supportedFeatures: string[];
	
	    static createFrom(source: any = {}) {
	        return new Vulnerability(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.vulnerabilityType = source["vulnerabilityType"];
	        this.severity = source["severity"];
	        this.target = source["target"];
	        this.url = source["url"];
	        this.payload = source["payload"];
	        this.description = source["description"];
	        this.proof = source["proof"];
	        this.recommendation = source["recommendation"];
	        this.responseHeaders = source["responseHeaders"];
	        this.responseContent = source["responseContent"];
	        this.supportedFeatures = source["supportedFeatures"];
	    }
	}

}

