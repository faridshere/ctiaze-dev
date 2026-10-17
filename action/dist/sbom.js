export class SbomError extends Error {
    name = "SbomError";
}
const isObj = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v) => typeof v === "string" && v.trim() && v.trim() !== "NOASSERTION"
    ? v.trim()
    : undefined;
/**
 * Parse CycloneDX JSON, SPDX 2.x JSON, a `{components:[...]}` / bare array of
 * components, or a plain text list (one `vendor product version`, `product
 * version`, purl or CPE per line; `#` starts a comment).
 */
export function parseSbom(text) {
    const trimmed = text.replace(/^﻿/, "").trim();
    if (!trimmed)
        throw new SbomError("SBOM is empty");
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
        let doc;
        try {
            doc = JSON.parse(trimmed);
        }
        catch (e) {
            throw new SbomError(`SBOM looks like JSON but does not parse: ${e.message}`);
        }
        return parseJsonSbom(doc);
    }
    return parseList(trimmed);
}
export function parseJsonSbom(doc) {
    if (Array.isArray(doc))
        return collect("components", doc.map(fromPlainObject));
    if (!isObj(doc))
        throw new SbomError("SBOM JSON must be an object or array");
    if (doc.bomFormat === "CycloneDX" || (doc.specVersion && Array.isArray(doc.components))) {
        return parseCycloneDx(doc);
    }
    if (typeof doc.spdxVersion === "string" || Array.isArray(doc.packages)) {
        return parseSpdx(doc);
    }
    if (Array.isArray(doc.components)) {
        return collect("components", doc.components.map(fromPlainObject));
    }
    if (Array.isArray(doc["@graph"])) {
        throw new SbomError("SPDX 3 JSON-LD is not supported yet; export SPDX 2.3 JSON instead");
    }
    throw new SbomError("Unrecognised SBOM JSON: expected CycloneDX (bomFormat), SPDX (spdxVersion) or {components:[...]}");
}
export function parseCycloneDx(doc) {
    const out = [];
    const walk = (list) => {
        if (!Array.isArray(list))
            return;
        for (const c of list) {
            if (!isObj(c))
                continue;
            // Files are not packages; nothing to look up.
            if (c.type === "file")
                out.push(null);
            else
                out.push(make(str(c.name), str(c.version), str(c.purl), str(c.cpe)));
            walk(c.components);
        }
    };
    // metadata.component is the thing the SBOM describes, not a dependency.
    walk(doc.components);
    return collect("cyclonedx", out);
}
export function parseSpdx(doc) {
    const described = new Set();
    if (Array.isArray(doc.documentDescribes)) {
        for (const id of doc.documentDescribes)
            if (typeof id === "string")
                described.add(id);
    }
    if (Array.isArray(doc.relationships)) {
        for (const r of doc.relationships) {
            if (isObj(r) &&
                r.relationshipType === "DESCRIBES" &&
                r.spdxElementId === doc.SPDXID &&
                typeof r.relatedSpdxElement === "string") {
                described.add(r.relatedSpdxElement);
            }
        }
    }
    const out = [];
    for (const p of Array.isArray(doc.packages) ? doc.packages : []) {
        if (!isObj(p))
            continue;
        const refs = Array.isArray(p.externalRefs) ? p.externalRefs.filter(isObj) : [];
        const ref = (...types) => {
            for (const t of types) {
                const hit = refs.find((r) => r.referenceType === t);
                if (hit)
                    return str(hit.referenceLocator);
            }
            return undefined;
        };
        const purl = ref("purl");
        const cpe = ref("cpe23Type", "cpe22Type");
        // The root package (a directory or image name) has no purl or cpe; skip it.
        if (typeof p.SPDXID === "string" && described.has(p.SPDXID) && !purl && !cpe) {
            out.push(null);
            continue;
        }
        out.push(make(str(p.name), str(p.versionInfo), purl, cpe));
    }
    return collect("spdx", out);
}
export function parseList(text) {
    const out = [];
    text.split(/\r?\n/).forEach((raw, i) => {
        const line = raw.replace(/#.*$/, "").trim();
        if (!line)
            return;
        if (line.startsWith("pkg:")) {
            out.push(fromPurl(line));
            return;
        }
        if (line.startsWith("cpe:")) {
            out.push(fromCpe(line));
            return;
        }
        const tokens = line.split(/[\s,]+/).filter(Boolean);
        if (tokens.length < 2) {
            throw new SbomError(`line ${i + 1}: expected "vendor product version" or "product version", got "${line}"`);
        }
        const version = tokens[tokens.length - 1];
        if (tokens.length === 2) {
            out.push({ name: tokens[0], version });
            return;
        }
        const vendor = tokens[0];
        const product = tokens.slice(1, -1);
        out.push({
            name: product.join(" "),
            version,
            cpe: `cpe:2.3:a:${cpeField(vendor)}:${cpeField(product.join("_"))}:${cpeField(version)}:*:*:*:*:*:*:*`,
        });
    });
    return collect("list", out);
}
function fromPlainObject(v) {
    if (!isObj(v))
        return null;
    return make(str(v.name), str(v.version), str(v.purl), str(v.cpe));
}
function fromPurl(purl) {
    // pkg:type/namespace/name@version?qualifiers#subpath
    const body = purl.replace(/[?#].*$/, "");
    const at = body.lastIndexOf("@");
    const path = at > 0 ? body.slice(0, at) : body;
    const version = at > 0 ? decodeURIComponent(body.slice(at + 1)) : "";
    const name = decodeURIComponent(path.split("/").pop() ?? path);
    return { name, version, purl };
}
function fromCpe(cpe) {
    // cpe:2.3:a:vendor:product:version:... or cpe:/a:vendor:product:version
    const parts = cpe.startsWith("cpe:/") ? ["cpe", "2.2", ...cpe.slice(5).split(":")] : cpe.split(":");
    const product = parts[4] ?? "";
    const version = parts[5] ?? "";
    return { name: product.replace(/_/g, " "), version: version === "*" || version === "-" ? "" : version, cpe };
}
function cpeField(s) {
    return s.toLowerCase().replace(/\s+/g, "_").replace(/([^a-z0-9._\-~*])/g, "\\$1");
}
function make(name, version, purl, cpe) {
    if (!name && purl)
        name = fromPurl(purl).name;
    if (!name)
        return null;
    if (!version && !purl && !cpe)
        return null;
    const c = { name, version: version ?? "" };
    if (purl)
        c.purl = purl;
    if (cpe)
        c.cpe = cpe;
    return c;
}
function collect(format, list) {
    const seen = new Set();
    const components = [];
    let skipped = 0;
    for (const c of list) {
        if (!c) {
            skipped++;
            continue;
        }
        const key = (c.purl ?? c.cpe ?? `${c.name}@${c.version}`).toLowerCase();
        if (seen.has(key)) {
            skipped++;
            continue;
        }
        seen.add(key);
        components.push(c);
    }
    return { format, components, skipped };
}
