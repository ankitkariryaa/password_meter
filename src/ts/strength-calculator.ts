import Dictionaries = require("./dict-misc");
import Helper = require("./helper");
// import JQuery = require("jquery");
import LZString = require("lz-string");

import PasswordMeter = require("./PasswordMeter");
import Config = require("./config");
import RuleFunctions = require("./rulefunctions");

export module StrengthCalculator {
	interface StrengthCallbackArguments {
		pwHash: string, 
		score: number, 
		compliant: boolean,
		problems: string, 
		feedback: string
	};
	type StrengthCallback = (arg0: StrengthCallbackArguments) => void;
	export class StrengthCalculator {
	helper: Helper.Helper.Helper;
	config: Config.Config.Config;
	verboseMode: boolean;
    // Mapping of passwords to score based on heurtistics
	private complaintPassword: {[key: string]: boolean} = {};
	private heuristicMapping: {[key: string]: number} = {};
	// Mapping of passwords to score based on neural networks
	private neuralnetMapping: {[key: string]: number} = {};
    // Mapping of passwords to public/sensitive feedback
    // potentialTODO that could get expensivex
    // potentialTODO structure this
    private feedbackMapping: {[key: string]: string} = {};
    private problemMapping: {[key: string]: string} = {};

	private displayCBMapping: {[key: string]: StrengthCallback} = {};

    constructor(verboseMode: boolean) {
		var registry = PasswordMeter.PasswordMeter.instance;
		this.helper = registry.getHelper();
        this.config = registry.getConfig();

		// this.$ = registry.getJquery();
		this.verboseMode = verboseMode;
	}

	getStrengthAndFeedback(cb: StrengthCallback, pw: string, pwHash: string, username: string, coreInfo: Array<string> = new Array(), allInfo: Array<string> = new Array()){
		this.displayCBMapping[pwHash] = cb;
		if (typeof (this.neuralnetMapping[pw]) === "undefined") {
	    	var nni = PasswordMeter.PasswordMeter.instance.getNN();
	    	var nn = nni.nn;
			// Signal that we are calculating it to avoid duplicate work
			this.neuralnetMapping[pw] = -1;
			// Asynchronously calculate neural network guess number
			nn.query_guess_number(pw);
		}
		this.calculateHeuristicStrength(cb, pw, pwHash, username, coreInfo, allInfo);

	}

    calculateHeuristicStrength(cb: StrengthCallback, pw: string, pwHash: string, username: string, coreInfo: Array<string>, allInfo: Array<string>): void {	    
		// We overwrite the password if they use contextual or blacklisted content
		// and we need the original to make the correct mappings
		var originalPW = pw;
		var pwComplaint = false;
		var problemText: Array<string> = [];

		var [heuristicScore, publictips, sensitivetips, reasonWhy] = this.getPasswordTips(pw, username, coreInfo, allInfo);

		var minReqObj = RuleFunctions.RuleFunctions.verifyMinimumRequirements(pw, username, coreInfo, allInfo);
		var policyGripes = [];
		console.log(minReqObj);
		if (!minReqObj.compliant){
			var detail = minReqObj.detail;
			for (var metric in detail.compliance) {
				if (!detail.compliance[metric]) {
					policyGripes.push(detail.explanation[metric]);
				}
			}
		}
		var majorProblems = JSON.stringify(policyGripes);
	
		var feedback = JSON.stringify({
				publictips: publictips,
				sensitivetips: sensitivetips,
				reasonWhy: reasonWhy,
			});

		this.heuristicMapping[pwHash] = heuristicScore;
		this.complaintPassword[pwHash] = minReqObj.compliant;
		this.problemMapping[pwHash] = majorProblems;
		this.feedbackMapping[pwHash] = feedback;


		this.displayRating(pwHash, originalPW.length);
    }    

    fromNNDisplayRating(pw:string):void {
    	let hash = this.helper.calculateHash(pw);
    	this.displayRating(hash, pw.length);
    }

	displayRating(pwHash: string, pwLength:number): void {
	  var overallScore = 0;
	  var numberOfScores = 0;
	  let cb = this.displayCBMapping[pwHash];
		if (pwLength> 0) {
			if (typeof (this.heuristicMapping[pwHash]) !== "undefined" && this.heuristicMapping[pwHash] >= 0) {
				overallScore = this.heuristicMapping[pwHash];
				numberOfScores++;
			}
			if (typeof (this.neuralnetMapping[pwHash]) !== "undefined"
			&& this.neuralnetMapping[pwHash] >= 0 && isFinite(this.neuralnetMapping[pwHash])) {
				numberOfScores++;
				if (overallScore == 0 || (overallScore > 0
					&& this.neuralnetMapping[pwHash] < overallScore)) {
					overallScore = this.neuralnetMapping[pwHash];
				}
			}
		}
		if (overallScore < pwLength / 2) {
		overallScore = pwLength / 2; // make people see at least some progess is happening
		}
		var r = <StrengthCallbackArguments> {
			pwHash: pwHash, 
			score: overallScore, 
			compliant: this.complaintPassword[pwHash],
			problems: this.problemMapping[pwHash], 
			feedback: this.feedbackMapping[pwHash]
		};
      //We receive a callback from the frontend, we pass the same callba
      cb(r);
    }


    getPasswordTips(pw:string, username:string, coreInfo: Array<string>, allInfo: Array<string>):[number, Array<string>, Array<string>,Array<string>]{
    		// Used to make 10^{15} fill 2/3rds of the bar
    		var scalingFactor = 67 / 15;

    		var originalPW = pw;
			var publictips: Array<string> = [];
			var sensitivetips: Array<string> = [];
			var reasonWhy: Array<string> = [];
			var problemText: Array<string> = [];

			// Return JSON objects from all of the rule functions
			var contextualObj = RuleFunctions.RuleFunctions.contextual(pw, [username]);
			pw = contextualObj.remaining;
			// If their whole password is contextual, we hit a type error
			if (typeof (pw) === "undefined") {
				pw = "";
			}
			var piObj = RuleFunctions.RuleFunctions.personalInfoInPassword(pw, coreInfo);
			pw = piObj.remaining;
			// If their whole password consists of personal information, we hit a type error
			if (typeof (pw) === "undefined") {
				pw = "";
			}
			var blacklistObj = RuleFunctions.RuleFunctions.blacklist(pw);
			pw = blacklistObj.remaining;
			// If their whole password is blacklisted, we hit a type error
			if (typeof (pw) === "undefined") {
				pw = "";
			}

			var lenObj = RuleFunctions.RuleFunctions.pwLength(pw);
			var classObj = RuleFunctions.RuleFunctions.characterClasses(pw);
			var duplicatedObj = RuleFunctions.RuleFunctions.duplicatedCharacters(pw);
			var repeatObj = RuleFunctions.RuleFunctions.repeats(pw);
			var patternsObj = RuleFunctions.RuleFunctions.keyboardPatterns(pw);
			var sequenceObj = RuleFunctions.RuleFunctions.repeatedSections(pw);
			var structureObj = RuleFunctions.RuleFunctions.structurePredictable(pw);
			var upperPredictableObj = RuleFunctions.RuleFunctions.uppercasePredictable(pw);
			var digitsPredictableObj = RuleFunctions.RuleFunctions.digitsPredictable(pw);
			var symbolsPredictableObj = RuleFunctions.RuleFunctions.symbolsPredictable(pw);
			var upperObj = RuleFunctions.RuleFunctions.countUC(pw);
			var lowerObj = RuleFunctions.RuleFunctions.countLC(pw);
			var digitObj = RuleFunctions.RuleFunctions.countDIGS(pw);
			var symbolObj = RuleFunctions.RuleFunctions.countSYMS(pw);
			var dateObj = RuleFunctions.RuleFunctions.identifyDates(pw);
			var minReqObj = RuleFunctions.RuleFunctions.verifyMinimumRequirements(pw, username, coreInfo, allInfo);
			var alphabeticsequenceObj = RuleFunctions.RuleFunctions.alphabeticSequenceCheck(pw);
			var commonsubstringObj = RuleFunctions.RuleFunctions.commonSubstringCheck(pw);
			var dictionaryCheckObj = RuleFunctions.RuleFunctions.combinedDictCheck(pw);
			var substringArrayNoFilter = pw.listSubstringsNoFilter(4);
			var commonpwObj = RuleFunctions.RuleFunctions.commonPwCheck(substringArrayNoFilter);
			var allInfoObj = RuleFunctions.RuleFunctions.allInfoInPassword(pw, allInfo);

			// Take the coefficients from our regression
			var coefficients = [1.530, 0.3129, 0.9912, 0.04637, -0.03885, -0.1172, -0.2976, -0.0008581, -0.3008, -0.5566, 0, 0.9108, 0.7369, 0.7578, 0, -0.1213, -0.2402, -0.1364, -0.5534, 1.927, 0.001496, -0.3946 /*Over class*/, -2, -1];
			var subscores: Array<number> = [1, lenObj.length, classObj.count, duplicatedObj.count,
				repeatObj.count, patternsObj.score, sequenceObj.count, structureObj.score,
				upperPredictableObj.score, digitsPredictableObj.score, symbolsPredictableObj.score,
				upperObj.count, lowerObj.count, digitObj.count, symbolObj.count, dateObj.count,
				alphabeticsequenceObj.count, commonsubstringObj.count, dictionaryCheckObj.length,
				dictionaryCheckObj.dictionaryTokens, dictionaryCheckObj.substitutionCommonness,
				commonpwObj.length, piObj.count, allInfoObj.count];
			// The first value is the intercept
			var overallScore = coefficients[0];
			var numberOfScores = 0;
			// Take the remaining coefficients and multiply by the rule function score
			for (var i = 1; i < coefficients.length; i++) {
				overallScore += coefficients[i] * subscores[i];
			}
			overallScore = overallScore * scalingFactor;

      // Save non-empty text feedback from the rule functions
			if (contextualObj.publicText.length > 0) {
				publictips.push(contextualObj.publicText);
				sensitivetips.push(contextualObj.sensitiveText);
				reasonWhy.push(contextualObj.reasonWhy);
				problemText.push(contextualObj.problemText);
			}
			if (piObj.publicText.length > 0) {
				publictips.push(piObj.publicText);
				sensitivetips.push(piObj.sensitiveText);
				reasonWhy.push(piObj.reasonWhy);
				problemText.push(piObj.problemText);
			}
			if (blacklistObj.publicText.length > 0) {
				publictips.push(blacklistObj.publicText);
				sensitivetips.push(blacklistObj.sensitiveText);
				reasonWhy.push(blacklistObj.reasonWhy);
				problemText.push(blacklistObj.problemText);
			}
			if (allInfoObj.publicText.length > 0) {
				publictips.push(allInfoObj.publicText);
				sensitivetips.push(allInfoObj.sensitiveText);
				reasonWhy.push(allInfoObj.reasonWhy);
				problemText.push(allInfoObj.problemText);
			}
			if (dictionaryCheckObj.publicText.length > 0
				&& !this.redundant(dictionaryCheckObj.problemText, problemText)) {
				publictips.push(dictionaryCheckObj.publicText);
				sensitivetips.push(dictionaryCheckObj.sensitiveText);
				reasonWhy.push(dictionaryCheckObj.reasonWhy);
				problemText.push(dictionaryCheckObj.problemText);
			}
			if (patternsObj.publicText.length > 0) {
				publictips.push(patternsObj.publicText);
				sensitivetips.push(patternsObj.sensitiveText);
				reasonWhy.push(patternsObj.reasonWhy);
				problemText.push(patternsObj.problemText);
			}
			if (repeatObj.publicText.length > 0) {
				publictips.push(repeatObj.publicText);
				sensitivetips.push(repeatObj.sensitiveText);
				reasonWhy.push(repeatObj.reasonWhy);
				problemText.push(repeatObj.problemText);
			}
			if (dateObj.publicText.length > 0) {
				publictips.push(dateObj.publicText);
				sensitivetips.push(dateObj.sensitiveText);
				reasonWhy.push(dateObj.reasonWhy);
				problemText.push(dateObj.problemText);
			}
			if (sequenceObj.publicText.length > 0) {
				publictips.push(sequenceObj.publicText);
				sensitivetips.push(sequenceObj.sensitiveText);
				reasonWhy.push(sequenceObj.reasonWhy);
				problemText.push(sequenceObj.problemText);
			}
			if (alphabeticsequenceObj.publicText.length > 0) {
				publictips.push(alphabeticsequenceObj.publicText);
				sensitivetips.push(alphabeticsequenceObj.sensitiveText);
				reasonWhy.push(alphabeticsequenceObj.reasonWhy);
				problemText.push(alphabeticsequenceObj.problemText);
			}
			if (commonpwObj.publicText.length > 0 && !this.redundant(commonpwObj.problemText, problemText)) {
				publictips.push(commonpwObj.publicText);
				sensitivetips.push(commonpwObj.sensitiveText);
				reasonWhy.push(commonpwObj.reasonWhy);
				problemText.push(commonpwObj.problemText);
			}
			if (upperPredictableObj.publicText.length > 0) {
				publictips.push(upperPredictableObj.publicText);
				sensitivetips.push(upperPredictableObj.sensitiveText);
				reasonWhy.push(upperPredictableObj.reasonWhy);
				problemText.push(upperPredictableObj.problemText);
			}
			if (digitsPredictableObj.publicText.length > 0) {
				publictips.push(digitsPredictableObj.publicText);
				sensitivetips.push(digitsPredictableObj.sensitiveText);
				reasonWhy.push(digitsPredictableObj.reasonWhy);
				problemText.push(digitsPredictableObj.problemText);
			}
			if (symbolsPredictableObj.publicText.length > 0) {
				publictips.push(symbolsPredictableObj.publicText);
				sensitivetips.push(symbolsPredictableObj.sensitiveText);
				reasonWhy.push(symbolsPredictableObj.reasonWhy);
				problemText.push(symbolsPredictableObj.problemText);
			}
			if (duplicatedObj.publicText.length > 0) {
				publictips.push(duplicatedObj.publicText);
				sensitivetips.push(duplicatedObj.sensitiveText);
				reasonWhy.push(duplicatedObj.reasonWhy);
				problemText.push(duplicatedObj.problemText);
			}
			if (lenObj.publicText.length > 0) {
				publictips.push(lenObj.publicText);
				sensitivetips.push(lenObj.sensitiveText);
				reasonWhy.push(lenObj.reasonWhy);
				//problemText.push(lenObj.problemText);
			}
			if (symbolObj.publicText.length > 0) {
				publictips.push(symbolObj.publicText);
				sensitivetips.push(symbolObj.sensitiveText);
				reasonWhy.push(symbolObj.reasonWhy);
				//problemText.push(symbolObj.problemText);
			}
			if (upperObj.publicText.length > 0) {
				publictips.push(upperObj.publicText);
				sensitivetips.push(upperObj.sensitiveText);
				reasonWhy.push(upperObj.reasonWhy);
				//problemText.push(upperObj.problemText);
			}
			if (digitObj.publicText.length > 0) {
				publictips.push(digitObj.publicText);
				sensitivetips.push(digitObj.sensitiveText);
				reasonWhy.push(digitObj.reasonWhy);
				//problemText.push(digitObj.problemText);
			}
			if (lowerObj.publicText.length > 0) {
				publictips.push(lowerObj.publicText);
				sensitivetips.push(lowerObj.sensitiveText);
				reasonWhy.push(lowerObj.reasonWhy);
				//problemText.push(lowerObj.problemText);
			}
			if (commonsubstringObj.publicText.length > 0 && !this.redundant(commonsubstringObj.problemText, problemText)) {
				publictips.push(commonsubstringObj.publicText);
				sensitivetips.push(commonsubstringObj.sensitiveText);
				reasonWhy.push(commonsubstringObj.reasonWhy);
				//problemText.push(commonsubstringObj.problemText);
			}
			if (structureObj.publicText.length > 0) {
				publictips.push(structureObj.publicText);
				sensitivetips.push(structureObj.sensitiveText);
				reasonWhy.push(structureObj.reasonWhy);
				//problemText.push(structureObj.problemText);
			}
			if(pw.length < this.config.length.minLength) 
				overallScore = 0;

		    if (overallScore < (originalPW.length / 2)) {
				overallScore = originalPW.length / 2;
	  		} else if (overallScore > 100) {
				overallScore = 100;
	  		}
	  return ([overallScore, publictips, sensitivetips, reasonWhy]);

    }

    setNeuralnetMapping(pw: string, value: number): void {
      this.neuralnetMapping[pw] = value;
    }

    // A function used to avoid showing redundant text feedback
    // generated by different scoring functions.
    // Returns true (redundant with previous feedback) or false (not redundant).
    redundant(problemText: string, arrayOfProblems: Array<string>): boolean {
      // Lowercase since some rule functions lowercase feedback
      problemText = problemText.toLowerCase();
      for (var i = 0; i < arrayOfProblems.length; i++) {
        arrayOfProblems[i] = arrayOfProblems[i].toLowerCase();
        if (arrayOfProblems[i].length > 0 && problemText.length > 0) {
          if ((arrayOfProblems[i].indexOf(problemText) >= 0
            && problemText.length >= 0.7 * arrayOfProblems[i].length)
            || (problemText.indexOf(arrayOfProblems[i]) >= 0
              && arrayOfProblems[i].length >= 0.7 * problemText.length)) {
            return true;
          }
        }
      }
      return false;
    }

    showNNRating(pw:string):number {
      return(this.neuralnetMapping[pw])
    }
  }
	(function() {
      var registry = PasswordMeter.PasswordMeter.instance;
      var verboseMode = false;
      var instance = new StrengthCalculator(verboseMode);
      registry.setStrengthCalculator(instance);
    }())

}
