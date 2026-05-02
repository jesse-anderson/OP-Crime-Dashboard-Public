# Oak Park Crime Data Science Dashboard

Independent, descriptive dashboard over public Oak Park Police Department
daily activity bulletins.

Live dashboard: https://opcrimeds.jesse-anderson.net/

Related map project: https://opcrime.jesse-anderson.net/

Public artifact repository: https://github.com/jesse-anderson/OP-Crime-Dashboard-Public

Author: Jesse Anderson

README date: 2026-05-02

## Important notice

This dashboard is an independent research and public analytics project. It is
not affiliated with, endorsed by, or operated in partnership with the Oak Park
Police Department, the Village of Oak Park, or any government agency.

The official Oak Park Police Department PDF bulletins remain the authoritative
source. This site reads, mirrors, summarizes, and analyzes public records. It
does not replace those records.

The dashboard is not real-time. The normal schedule is: the mapping pipeline
updates at midnight and noon Central Time, and this dashboard rebuilds at 1:00
AM and 1:00 PM Central Time. Each dashboard build has an as-of date shown in the
app. New or corrected OP PD bulletins appear only after the upstream data and
this dashboard have both rebuilt.

Do not use this dashboard for legal, law enforcement, housing, employment,
insurance, business, political, safety, operational, or personal decision
making. The charts, rankings, topic models, search results, zone summaries,
weather comparisons, and similar incident panels are exploratory and unofficial.

## What this project is

The Oak Park Crime Data Science Dashboard is a historical, descriptive layer on
top of public Oak Park police activity reports. It takes the structured output
from the companion Oak Park crime map project and turns it into resident-readable
comparisons:

- How do current year-to-date report counts compare with the same window last
  year?
- Which offenses are most common right now?
- Which policing zones have the most reports, and how does that look after
  adjusting for estimated resident population?
- Do reported incident times differ by offense, weekday, season, holiday,
  daylight, or weather cohort?
- What recurring themes appear in the narrative text?
- Can a reader search public narratives and open the original PDF behind each
  result?
- When viewing one incident, which other narratives read most like it?

The dashboard is built for residents, local reporters, civic researchers, and
people who want a clearer way to inspect a public record stream. It is meant to
support comparison and context, not prediction.

## What this project is not

This is not a crime forecast. It does not predict where the next crime will
happen. It does not score addresses, blocks, people, businesses, or
neighborhoods for risk.

This is not an official records system. If a bulletin is wrong, incomplete, or
later amended, the correction has to happen at the official source. The dashboard
will pick up amended source data on a future rebuild.

This is not a suspect lookup tool. The only descriptor filtering claimed here is
for race and ethnicity. Public topic labels and the search index use that
blocklist. Gender, age, clothing, build, and other physical descriptors are not
filtered from displayed narratives.

This is not a complete picture of public safety in Oak Park. It only contains
what appears in the published police bulletins and what the pipeline can parse.
Unreported incidents, delayed reporting, source errors, parsing failures, and
classification changes are all outside the dashboard's control.

## How to read the numbers

An "incident" means a row parsed from the published Oak Park Police Department
bulletin stream. A row is a reported incident in the public source data, not a
court finding and not an independent verification of what happened.

"YTD" means January 1 through the dashboard's current as-of date. "Prior YTD"
means January 1 through the same calendar date in the prior year.

YTD change is computed as:

```text
(current YTD count - prior YTD count) / prior YTD count * 100
```

If the prior year count is zero, the percent change is left null rather than
forcing a misleading number.

"Zone" means one of the eight Oak Park policing zones from the April 2024 zone
map. Historical incidents are assigned to those current boundaries. That makes
the current dashboard internally consistent, but it also means older incidents
are not shown under whatever boundary may have existed at the time.

"Per 1,000 residents" means the number of incidents located in a zone divided by
that zone's estimated resident population, multiplied by 1,000. It is not a
resident risk estimate. It is a rough normalization for comparing zones of
different sizes.

"Lift" compares a zone or topic share against a village-wide baseline. For
offenses, the formula is:

```text
(offense count in zone / all incidents in zone)
/
(offense count village-wide / all incidents village-wide)
```

A lift of 2.0 means the offense makes up twice as much of that zone's incident
mix as it does in the village overall. Lift values are suppressed when the
underlying count is too small to be useful.

"Topic" means an unsupervised cluster of narrative text. Topics are useful
groups, not official categories. Some narratives are deliberately left
unclustered as noise.

"Similar incidents" means narratives that are close to one another in embedding
space. It does not mean the same person, same crew, same address, or same legal
case.

## Dashboard guide

### Overview

The Overview page is the landing page. It gives a quick read on the current
state of the dataset:

- Current YTD incident count
- Prior YTD comparison
- Top YTD offense
- Most active zone
- Most active day of week
- Recent pulse windows for 7 days, 14 days, 28 days, 90 days, and 365 days
- A custom comparison chart for lining up arbitrary date ranges
- Top YTD offenses and zones
- Data coverage notes

The goal is to make the main comparisons visible before a reader starts looking
at a map or remembering a recent incident near them.

### Time

The Time page describes how reports move across the calendar and clock:

- Long-run daily trend with a moving average
- Year by month heatmap
- Month-of-year profile
- Hour by day-of-week heatmap
- Calendar heatmap
- Holiday and weekend comparison
- Darkness share by offense
- Weather cohorts based on Chicago Midway daily observations

Time ranges are handled as intervals. If a theft is reported as happening
between 6:00 PM and 6:00 AM, the dashboard does not pretend it happened at one
exact hour. For hour profiles, that incident is spread across the hours it
touched.

Weather, holidays, and darkness panels are descriptive cohorts. They show how
counts differed in this dataset under those conditions. They do not claim that
weather, holidays, or darkness caused the incidents.

### Place

The Place page works at policing-zone granularity:

- Zone choropleth for YTD count, lifetime count, YTD change, and YTD incidents
  per 1,000 estimated residents
- Zone cards with YTD counts, prior YTD comparison, lifetime counts, and top
  offenses
- Zone detail panels for demographics, narrative signals, top offenses,
  distinctive offenses, hour profile, and day-of-week profile
- Explicit count of rows not assigned to an Oak Park dashboard zone

The dashboard does not create address or block risk scores. Zone-level
aggregation is a deliberate limit.

Demographic context comes from Census ACS tract data interpolated to the eight
policing zones. It is used only for zone-level context. Census fields are not
attached to individual incident records, addresses, narratives, or named people.

### Topics

The Topics page groups public narratives into recurring themes. The pipeline:

1. Encodes each narrative with a sentence embedding model.
2. Reduces the vector space with UMAP.
3. Clusters dense regions with HDBSCAN.
4. Labels clusters with c-TF-IDF terms.
5. Filters public labels to remove terms from the race and ethnicity blocklist.

Each topic card shows size, label words, zone distribution, zone lift, top
offenses, and sample records. The page also explains the village baseline used
for lift.

Topics are helpful for browsing the shape of thousands of short narratives. They
are not official offense categories, legal conclusions, or validated findings.

### Search

The Search page is keyword search over public narrative summaries. It uses BM25,
a standard document ranking formula. It supports:

- Plain terms, such as `bicycle porch`
- Required terms, such as `+bicycle porch`
- Excluded terms, such as `bicycle -arrest`
- Prefix wildcards, such as `bicyc*`

Search results link back to the source Oak Park Police Department PDF whenever a
source URL is available.

Terms from the race and ethnicity blocklist are stripped from the search index
as a guardrail. The displayed narrative still mirrors the public source text.
The search index is not a full redaction system and should not be treated as
one.

Search can still surface sensitive or identifying information that appears in
the public PDFs. It is a retrieval tool over the published bulletin text, not a
privacy screen.

### Incident pages

Incident pages can be opened from search results, topic samples, or offense
drill-downs. Each page shows the seed record and a source PDF link. It can also
load related narrative panels:

- Most similar incidents
- Anti-neighbors, meaning records in the same broad topic that read least like
  the seed

The similarity engine uses quantized sentence embeddings and computes cosine
similarity in the browser. It re-ranks for diversity and collapses runs of three
or more neighbors at the same address so one location does not dominate the
panel.

Similarity is a reading aid. It is not evidence and not a case linkage tool.

### Offense drill-downs

Common offenses get precomputed drill-down pages. These show:

- Lifetime count
- YTD count and prior YTD comparison
- Monthly history
- Hour by day-of-week pattern
- Zone distribution and lift
- Narrative signals
- Recent records with bulletin links

Rare offenses are not given full drill-down pages because tiny panels can create
small-count noise. Search is the better way to find rare records.

### About

The About page is the method and caveat page inside the dashboard. It covers:

- What the dashboard is and is not
- Source data
- Data coverage
- Tab guide
- Related narrative method
- Geographic aggregation
- Time normalization
- Narrative keyword scanning
- Embeddings
- Topic modeling
- BM25 search
- Ethics and guardrails
- Known limitations

## Data sources

### Oak Park Police Department bulletins

The canonical source is the Oak Park Police Department's published PDF bulletin
stream. The companion Oak Park crime map project parses those PDFs into
structured artifacts. This dashboard reads those generated artifacts and builds
additional derived views.

Every narrative displayed by the dashboard should be treated as a mirror of the
source material, not as an edited or official restatement.

### Oak Park policing zones

Zone assignment uses the April 2024 Oak Park Police Department zone boundary
map. Incidents with no usable geocode or no dashboard zone assignment are
excluded from zone panels and counted explicitly as unassigned.

The dashboard does not impute missing zones.

### Weather

Weather comes from Meteostat station observations for Chicago Midway. Midway is
near Oak Park and has useful coverage across the dashboard's date range.

The weather panel uses daily cohorts such as rainy, snowy, hot, cold, and
freezing. Cohorts with too few days are suppressed because the ratio would be
too noisy.

### Calendar and daylight

The pipeline adds calendar context such as holidays, weekends, sunrise, sunset,
civil dawn, civil dusk, and darkness. These fields are joined at the aggregate
date level.

Holiday panels compare mean incidents per calendar day, not raw incident counts
with no denominator. That distinction matters because holidays are rare and the
number of holiday dates is the natural denominator.

### Census ACS

Demographic context comes from the U.S. Census Bureau American Community Survey
five-year estimates. The current dashboard uses tract-level ACS data for the
2018 to 2022 release, interpolated to Oak Park policing zones.

This product uses the Census Bureau Data API but is not endorsed or certified by
the Census Bureau.

Count-like variables, such as population and households, are area-weighted from
tracts into zones. Rate-like variables, such as median income, median age, and
percentage fields, use population-weighted averages.

## Processing summary

The dashboard build is a static publication pipeline. Expensive work happens
before the public site is deployed.

At a high level:

1. Fetch the structured crime artifacts from the companion map project.
2. Parse OP PD time strings into start, end, midpoint, and duration fields.
3. Add calendar, daylight, and weather context.
4. Scan narratives with curated keyword lists for event-level signals.
5. Build blocklist-filtered narrative text for semantic features.
6. Encode narratives with a sentence embedding model.
7. Quantize embeddings for browser delivery.
8. Fit narrative topics and produce public label words.
9. Interpolate Census ACS context to policing zones.
10. Build Overview, Time, Place, Topics, Search, Incident, and Offense
    artifacts.
11. Compile the static web application.
12. Publish the compiled site and generated public artifacts.

The public dashboard is a static single-page application. The current app reads
generated JSON and GeoJSON panels directly. Browser-side search and similarity
also load compiled WASM, and similarity loads binary vector and metadata
artifacts after an incident page requests them.

## Public repository shape

The public repository is generated output for the dashboard. It is not the
source repository for the private build pipeline.

The public repository README is generated from `README_PUBLIC.md` in the private
dashboard repository during each publish.

Public artifacts may include:

- Compiled HTML, JavaScript, and CSS
- Compiled WASM used by browser-side search or similarity code
- Public JSON, GeoJSON, parquet, and binary data artifacts produced by the
  pipeline
- A manifest with sizes, hashes, and URLs for large R2 artifacts
- Cloudflare Pages configuration files needed to serve the static app
- Small Cloudflare Pages Function files used to proxy R2 artifacts from the
  same origin

The public artifact repository should not contain:

- Python pipeline source
- Application TypeScript source
- Rust source
- Model weights
- Local caches
- API keys
- Environment files
- Raw private enrichment intermediates

## Method notes

### Time ranges

Police reports often describe a time window rather than a point in time. The
dashboard keeps start, end, midpoint, and duration fields instead of collapsing
everything to one guessed hour.

Hour and day-of-week charts spread a report across the hours it touches. A
12-hour overnight incident contributes one twelfth to each touched hour. This
makes the profile less sharp, but it is more honest than pretending the report
gave an exact time.

### Year-to-date comparison

YTD comparisons use calendar-matched windows. For example, if the current build
is through April 28, 2026, the prior YTD window is January 1 through April 28,
2025.

This is not a model. It is a plain comparison that matches how most residents
ask the question.

### Zone aggregation

Zone panels use the eight current Oak Park policing zones. The dashboard
reports rows that could not be assigned to a dashboard zone and does not fill
them in with guesses.

Per-capita rates use estimated resident population. Small zones are still shown,
but the interface marks small denominators because per-capita values can swing
more sharply there.

### Distinctive offenses

Distinctive offenses use lift rather than raw count. Raw count answers "what is
common here?" Lift answers "what is more concentrated here than village-wide?"

Both views matter. A zone can have many theft reports because theft is common
everywhere. Lift helps show whether theft is unusually concentrated in that
zone's mix.

### Narrative signals

Narrative signal cards use curated keyword lists for practical questions like:

- Did the narrative mention a firearm term?
- Did it mention an unlocked vehicle?
- Did it mention forced entry?
- Did it mention catalytic converters?
- Which stolen item categories appear most often?
- Which location types appear most often?

The denominator is the number of incidents in that group that have a scanned
narrative, not all incidents. A missing narrative is not the same thing as a
narrative with no matching term.

The signal names are intentionally cautious. "Arrest mentioned" does not mean
"case cleared by arrest." It means the narrative text contained an arrest term.

### Embeddings and similarity

An embedding is a vector that represents the meaning of a narrative. The
dashboard uses embeddings for topic modeling and related narrative panels.

Before text is sent to the embedding model, the pipeline applies a
blocklist-based race and ethnicity scrub policy. This does not make the model
bias-free, and it is not a broad descriptor scrubber. Gender, age, clothing,
build, and other physical descriptors remain available when they are present in
the public source text.

The full-precision embeddings are too large for practical browser use, so the
published vectors are quantized to signed 8-bit integers. The quantization was
checked against full-precision neighbor rankings before being used for the
public similarity feature.

### Topic modeling

Topic modeling is exploratory. It helps find recurring narrative themes without
requiring every theme to be hand-written first.

The pipeline allows noise. Some narratives do not belong to a clear cluster,
and forcing every row into a topic would make the page cleaner while making it
less honest.

Public labels are filtered so terms from the race and ethnicity blocklist do
not become the headline words for a topic. Filtering changes the displayed label
words, not the underlying cluster membership.

### Search

Search uses BM25 over tokenized narratives. BM25 rewards terms that appear in a
document and gives more weight to terms that are rarer across the corpus.

The search index drops stopwords, short tokens, pure numbers, and terms from the
race and ethnicity blocklist. Query parsing and scoring run in the browser.

## Ethics and guardrails

The project uses public records, but aggregation changes access. A PDF buried on
a public site and a fast searchable dashboard are not the same experience. The
dashboard therefore keeps several limits:

- No predictive policing.
- No per-address risk scores.
- No per-block risk scores.
- No person risk scores.
- No intentional race or ethnicity mining in curated features.
- No terms from the race and ethnicity blocklist in public topic labels.
- No terms from the race and ethnicity blocklist in the search index.
- Blocklist-based race and ethnicity scrubbing before embedding input.
- Sensitive or identifying narratives may still appear when they are present in
  the public OP PD PDFs.
- Every displayed narrative links back to the source PDF when a source URL is
  available.
- Methodology and caveats are part of the product, not a footnote.

These limits do not make the project perfect. They define what the dashboard is
willing to do and what it is not willing to do.

## Known limitations

The source is incomplete. Incidents that are not reported to police do not
appear in the dashboard.

The source is delayed and human-entered. Bulletins may contain mistakes,
omissions, inconsistent labels, or later corrections.

Parsing can fail. PDF extraction, geocoding, time parsing, narrative matching,
classification, and artifact generation can omit, misread, duplicate, or
misclassify records.

Geography is approximate. Some reports are block-level. Some incidents have
locations outside Oak Park. Some rows have no usable geocode. Current 2024 zone
boundaries are used across the full historical dataset.

Census context is approximate. ACS tract values are interpolated to policing
zones, and tract values themselves are estimates. The dashboard does not know
where within a tract people live, so interpolation depends on standard but
imperfect assumptions.

Weather context is approximate. Chicago Midway is close to Oak Park, but it is
not a weather sensor on every Oak Park block.

Machine learning output is exploratory. Topic clusters, label words, and similar
incident results are starting points for reading source records. They are not
standalone findings.

Small counts are noisy. Rare offenses, rare weather cohorts, and narrow
time-zone-offense slices can move dramatically with only a few records.

Correlations are not causes. A chart that shows different counts on holidays,
rainy days, hot days, or dark hours does not prove the condition caused the
difference.

## Corrections and contact

For official records, complete data, or authoritative information, consult the
Oak Park Police Department and other appropriate official sources.

If a specific OP PD bulletin appears to contain an error, contact OP PD. The
dashboard mirrors the official source and will pick up source-side corrections
on a future rebuild.

For dashboard issues, such as a broken chart, stale artifact, confusing label,
or methodology question, use the public repository:

https://github.com/jesse-anderson/OP-Crime-Dashboard-Public

Author contact:

- Email: jesse@jesse-anderson.net
- GitHub: https://github.com/jesse-anderson

## Suggested citation

If you cite the dashboard, include the site name, author, URL, and access date:

```text
Jesse Anderson, Oak Park Crime Data Science Dashboard,
https://opcrimeds.jesse-anderson.net/, accessed YYYY-MM-DD.
```

For any claim about an individual record, cite the original Oak Park Police
Department PDF rather than this dashboard.
