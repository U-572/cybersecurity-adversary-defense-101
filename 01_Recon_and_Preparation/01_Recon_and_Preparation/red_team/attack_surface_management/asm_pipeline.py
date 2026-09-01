import asyncio
# asyncio:
# Python's built-in library for asynchronous programming. It allows the program
# to wait for network activity while still managing other tasks instead of
# freezing while it waits for one operation to finish.

import certstream
# certstream:
# A third-party Python package used to consume Certificate Transparency (CT)
# events from the public CertStream service.
#
# Certificate Transparency is a public record of SSL/TLS certificates.
# certstream lets this program listen for newly observed certificates so it
# can identify domain names associated with the target keyword.
#
# IMPORTANT:
# certstream is NOT included with Python. It must be installed separately:
#     python3 -m pip install certstream
#
# For this GitHub project, also add:
#     certstream
# to requirements.txt.


# LAYMAN'S EXPLANATION:
# This program watches public internet records for information associated
# with a target name. Think of it as an automated researcher building a map
# of an organization's publicly visible internet infrastructure.
#
# It keeps track of discovered domain names and network ranges and reacts
# when new certificates associated with the target appear in the public
# Certificate Transparency stream.
#
# The prototype is divided into four modules:
#   1. ASN/BGP Discovery        - Represents identifying associated IP ranges.
#   2. Certificate Monitoring   - Watches for newly issued public certificates.
#   3. Predictive Permutation   - Generates possible related infrastructure names.
#   4. Wildcard Handling        - Recognizes wildcard certificates and processes
#                                 them differently from ordinary certificates.
#
# Portfolio Note:
# Some functionality is intentionally represented as prototype/abstracted
# behavior. For example, the ASN module currently uses a documentation IP
# range rather than performing a live BGP lookup.

# DoW Red Team - Autonomous Attack Surface Pipeline (v2.0)
# Includes Wildcard Certificate Detection and Evasion Logic.


class ASMPipeline:
    # Defines the ASMPipeline class.
    # A class is a reusable blueprint that groups the pipeline's data and functions.

    def __init__(self, target_keyword):
        # __init__ runs automatically whenever a new ASMPipeline object is created.
        # target_keyword is the word/domain fragment the pipeline will watch for.

        self.target = target_keyword.lower()
        # Stores a lowercase copy of the target keyword so matching is case-insensitive.

        self.known_subdomains = set()
        # Creates an empty set for discovered subdomains.
        # A set automatically prevents duplicate entries.

        self.asn_ip_blocks = set()
        # Creates another set for network ranges associated with the target.

        self.loop = None
        # Stores a reference to the MAIN asyncio event loop.
        #
        # This matters because CertStream runs in a worker thread below.
        # Worker threads do not automatically have their own asyncio event loop.
        # Saving the main loop lets the callback safely schedule async work back
        # onto the correct event loop.


    async def module_1_asn_extractor(self):
        # Defines Module 1 as an asynchronous function.
        # "async" means this function can cooperate with Python's asyncio event loop.

        """Prototype ASN/BGP discovery module using placeholder network data."""
        # This docstring describes what the CURRENT code actually does.

        print(f"[*] [Module 1] Simulating ASN/BGP discovery for {self.target}...")
        # Reports that this module is currently a prototype rather than a live BGP query.

        await asyncio.sleep(1)
        # Pauses this coroutine for one second without blocking the entire asyncio loop.
        # IMPORTANT: This SIMULATES work; it does not actually query BGP data.

        self.asn_ip_blocks.add("203.0.113.0/24")
        # Adds a documentation/example IP network to the set.
        # 203.0.113.0/24 is reserved for examples and documentation.

        print("[+] [Module 1] Added placeholder documentation IP block.")
        # Reports that the prototype ASN stage has completed.


    async def module_3_predictive_permutation(self, base_name):
        # Defines Module 3.
        # It receives a discovered base name and constructs possible related names.

        """Generates probable infrastructure names based on known conventions."""

        print(f"    [*] [Module 3] Running predictive permutation on base: {base_name}")
        # Reports which base name is currently being processed.

        environments = ['dev', 'test', 'stage', 'uat']
        # Creates a list of common environment labels:
        # development, testing, staging, and User Acceptance Testing.

        for env in environments:
            # Loops through each environment name one at a time.

            guess = f"{env}-{base_name}"
            # Combines the environment label with the supplied base name.
            #
            # Example:
            # base_name = "api.example.com"
            # env       = "dev"
            # result    = "dev-api.example.com"

            print(f"    [+] [Module 3] Generated high-probability guess: {guess}")
            # Displays the generated candidate.

            # Abstracted: Trigger async DNS resolver here
            # IMPORTANT:
            # The current prototype stops here.
            # It generates candidate names but does NOT actually perform the DNS
            # resolution that would determine whether the candidate exists.


    async def module_4_wildcard_evasion(self, domain):
        # Defines Module 4.
        # This handles Certificate Transparency results beginning with "*.".

        """
        Handles wildcard certificate results by generating candidate hostnames.

        #laymens: If a public certificate contains '*.target.com', the program
        removes the asterisk and generates plausible service names underneath
        that domain for further research.
        """

        print(f"\n[!] [Module 4] Wildcard certificate detected -> {domain}")
        # Reports that a wildcard certificate was encountered.

        print("    [*] Generating candidate infrastructure names...")
        # Reports that the program will generate candidate names from the wildcard domain.

        base_domain = domain.replace("*.", "", 1)
        # Removes only the FIRST wildcard prefix.
        #
        # Example:
        # "*.example.com"
        # becomes:
        # "example.com"

        common_bases = ['api', 'app', 'vpn', 'portal']
        # Defines several common infrastructure/service labels.

        for base in common_bases:
            # Processes each service label individually.

            await self.module_3_predictive_permutation(f"{base}.{base_domain}")
            # Constructs a base hostname and sends it to Module 3.
            #
            # Example:
            # base_domain = example.com
            # base        = api
            #
            # Module 3 receives:
            # api.example.com


    def _schedule_coroutine(self, coroutine):
        # Safely sends async work from the CertStream worker thread back to the
        # MAIN asyncio event loop.

        if self.loop is None or self.loop.is_closed():
            # If the event loop has not been initialized, or has already closed,
            # there is nowhere safe to schedule the coroutine.

            coroutine.close()
            # Closes the coroutine so Python does not warn that it was never awaited.

            return

        asyncio.run_coroutine_threadsafe(coroutine, self.loop)
        # Thread-safe scheduling is required here because _certstream_callback()
        # may execute inside the worker thread created by run_in_executor().
        #
        # This FIXES the earlier approach:
        #
        #     asyncio.get_event_loop()
        #
        # which could fail inside the CertStream worker thread with:
        #
        # RuntimeError: There is no current event loop in thread ...


    def _certstream_callback(self, message, context):
        # Callback function supplied to CertStream.
        #
        # A callback is a function that another component calls automatically
        # whenever a relevant event occurs.

        """Processes Certificate Transparency events received from CertStream."""

        if not isinstance(message, dict):
            # Defensive validation:
            # Ignore unexpected messages that are not Python dictionaries.

            return

        if message.get('message_type') != "certificate_update":
            # Ignores unrelated CertStream events.

            return

        all_domains = (
            message.get('data', {})
            .get('leaf_cert', {})
            .get('all_domains', [])
        )
        # Safely navigates the CertStream message structure.
        #
        # Using .get() instead of:
        #
        #     message['data']['leaf_cert']['all_domains']
        #
        # prevents KeyError exceptions if an unexpected event does not contain
        # one of those fields.

        for raw_domain in all_domains:
            # Examines every domain contained in the certificate.

            if not isinstance(raw_domain, str):
                # Ignore malformed/non-string entries.

                continue

            domain = raw_domain.lower().strip()
            # Converts the domain to lowercase and removes accidental whitespace.
            #
            # This gives us consistent case-insensitive comparisons.

            if self.target not in domain:
                # Ignore certificates unrelated to our target keyword.

                continue

            if domain in self.known_subdomains:
                # Ignore a domain if we already processed it.

                continue

            self.known_subdomains.add(domain)
            # Records the domain so subsequent appearances are not processed again.

            if domain.startswith("*."):
                # Determines whether this is a wildcard certificate.

                self._schedule_coroutine(
                    self.module_4_wildcard_evasion(domain)
                )
                # Sends Module 4 back to the MAIN asyncio event loop safely.
                #
                # We DO NOT call asyncio.get_event_loop() from this callback because
                # this callback may be executing inside a different worker thread.

            else:
                # Runs when an ordinary, non-wildcard domain was discovered.

                print(f"\n[!] [Module 2] LIVE ALERT: New infrastructure -> {domain}")
                # Displays the newly observed domain.

                self._schedule_coroutine(
                    self.module_3_predictive_permutation(domain)
                )
                # IMPORTANT FIX:
                #
                # The original version used:
                #
                #     domain.split('.')[0]
                #
                # For:
                #
                #     portal.example.com
                #
                # that produced only:
                #
                #     portal
                #
                # Module 3 would then generate:
                #
                #     dev-portal
                #
                # rather than:
                #
                #     dev-portal.example.com
                #
                # Passing the complete domain preserves the actual domain suffix.


    async def module_2_live_monitor(self):
        # Defines Module 2: the CertStream monitoring component.

        """Connects to the CertStream WebSocket."""

        print(f"[*] [Module 2] Connecting to global CertStream for '{self.target}'...")
        # Reports the keyword being monitored.

        self.loop = asyncio.get_running_loop()
        # Saves the MAIN asyncio event loop.
        #
        # CertStream will run in a worker thread.
        # Its callback needs this stored reference to safely schedule asynchronous
        # Module 3/4 work back onto this loop.

        await self.loop.run_in_executor(
            None,
            lambda: certstream.listen_for_events(
                self._certstream_callback,
                url='wss://certstream.calidog.io/'
            )
        )
        # certstream.listen_for_events() is a BLOCKING operation:
        # it continuously waits for Certificate Transparency events.
        #
        # run_in_executor() moves that blocking listener into a worker thread.
        #
        # This allows the MAIN asyncio event loop to remain available for
        # asynchronous tasks created by Module 3 and Module 4.


async def main():
    # Defines the program's main asynchronous entry point.

    target = "example"
    # Abstracted target keyword.
    #
    # The program will look for Certificate Transparency results containing
    # this string.
    #
    # IMPORTANT:
    # This is currently hardcoded rather than supplied through command-line
    # arguments or a configuration file.

    pipeline = ASMPipeline(target)
    # Creates an instance of ASMPipeline.
    #
    # This automatically calls:
    #
    #     __init__("example")

    await pipeline.module_1_asn_extractor()
    # Runs Module 1 first and waits for it to finish.
    #
    # In the current prototype this produces placeholder ASN/IP information.

    await pipeline.module_2_live_monitor()
    # Starts Module 2.
    #
    # Because the CertStream listener continuously waits for certificate events,
    # the program normally remains running here while monitoring the stream.


if __name__ == "__main__":
    # Python sets __name__ to "__main__" when this file is executed directly.
    #
    # This prevents main() from automatically executing if another Python
    # program simply imports this file.

    asyncio.run(main())
    # Creates and manages the asyncio event loop and executes main().
    #
    # This is effectively the command that starts the complete pipeline.
