const https = require("https");
const requestOptions = {
	hostname: process.env.GITHUB_API_URL.replace(new RegExp('^https://'), ''),
	port: 443,
	path: `/repos/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}/jobs`,
	method: "GET",
	headers: {"User-Agent": `GHA-${process.env.GITHUB_RUN_ID}`},
};
const jobName = process.env.JOB_NAME;
console.log(`Name of the job to wait for is ${jobName}`);
console.log(`Request options:${JSON.stringify(requestOptions)}`);
console.log(`Environment:${JSON.stringify(process.env)}`);

async function jobConclusion() {
	return new Promise((success, failure) => {
		const request = https.request(requestOptions, response => {
			let body = "";
			response.on("data", chunk => {
				body += chunk;
			});
			response.on("end", () => {
				success(JSON.parse(body));
			});
		});
		request.on("error", error => {
			failure(error);
		});
		request.end();
	});
}


async function sleep(timeInMs) {
	return new Promise(success => setTimeout(success, timeInMs));
}

async function waitForConclusion() {
	const seconds = 10;
	let conclusion, json, jobs, job;
	const maxTries = 3;
	let tries = 0;
	do {
		console.log(`Waiting ${seconds} seconds...`);
		await sleep(seconds * 1000);
		try {
			json = await jobConclusion();
		} catch (exception) {
			tries++;
			console.error(exception.message);
			if (tries < maxTries) {
				console.error(`Trying again (attempt ${tries} of ${maxTries})`);
				continue;
			}
			console.error(`Already made ${tries} of  ${maxTries} attempts. Aborting...`);
			break;
		}
		jobs = json.jobs;
		if (!(jobs instanceof Array)) {
			console.log(`No jobs found! Response: ${JSON.stringify(json)}`);
			break;
		}
		job = jobs.reduce((result, job) => job.name === jobName ? job : result, null);
		console.log(`Job status: ${job.status}`);
		conclusion = job.conclusion;
	} while (typeof conclusion !== "string");
	console.log(`${jobName} conclusion: ${conclusion}`);
	return conclusion !== "success";
}

waitForConclusion().then(exitCode => process.exit(exitCode));