use std::io::{self, Write};

use crate::util::xml::xml_element::XmlElement;
use crate::util::xml::xml_exception::XmlException;
use crate::util::xml::xml_pull_parser::XmlPullParser;

const IDF_SIZE: usize = 512;
const TF_SIZE: usize = 64;

/// Holds the weighting tables and scoring parameters used to score LSHVector similarity.
///
/// Port of `generic.lsh.vector.WeightFactory`.
pub struct WeightFactory {
    /// Weights associated with (normalized) idf counts.
    idfweight: [f64; IDF_SIZE],
    /// Weights associated with tf (term frequency) counts.
    tfweight: [f64; TF_SIZE],
    /// Scale to which idf weights are normalized = -log2(probability of 1000th most common hash).
    weightnorm: f64,
    /// Hash flipping probability in causal model, param0.
    probflip0: f64,
    /// Hash flipping probability in causal model, param1.
    probflip1: f64,
    /// Hash addition/removal probability, param0.
    probdiff0: f64,
    /// Hash addition/removal probability, param1.
    probdiff1: f64,
    /// Final scaling to all weights.
    scale: f64,
    /// Final correction to score.
    addend: f64,
    probflip0_norm: f64,
    probflip1_norm: f64,
    probdiff0_norm: f64,
    probdiff1_norm: f64,
}

impl Default for WeightFactory {
    fn default() -> Self {
        Self {
            idfweight: [0.0; IDF_SIZE],
            tfweight: [0.0; TF_SIZE],
            weightnorm: 0.0,
            probflip0: 0.0,
            probflip1: 0.0,
            probdiff0: 0.0,
            probdiff1: 0.0,
            scale: 0.0,
            addend: 0.0,
            probflip0_norm: 0.0,
            probflip1_norm: 0.0,
            probdiff0_norm: 0.0,
            probdiff1_norm: 0.0,
        }
    }
}

impl WeightFactory {
    /// Creates a new, zeroed `WeightFactory`.
    pub fn new() -> Self {
        Self::default()
    }

    fn update_norms(&mut self) {
        self.probflip0_norm = self.probflip0 * self.scale;
        self.probflip1_norm = self.probflip1 * self.scale;
        self.probdiff0_norm = self.probdiff0 * self.scale;
        self.probdiff1_norm = self.probdiff1 * self.scale;
    }

    /// Returns the number of weights in the IDF portion of the table.
    pub fn get_idf_size(&self) -> usize {
        self.idfweight.len()
    }

    /// Returns the number of weights in the TF portion of the table.
    pub fn get_tf_size(&self) -> usize {
        self.tfweight.len()
    }

    /// Returns the number of floating-point entries needed to serialize the factory.
    pub fn get_size(&self) -> usize {
        self.idfweight.len() + self.tfweight.len() + 7
    }

    /// Returns the IDF weight at the given position.
    pub fn get_idf_weight(&self, val: usize) -> f64 {
        self.idfweight[val]
    }

    /// `val` is the term count (-1). Returns the TF weight for the given count.
    pub fn get_tf_weight(&self, val: usize) -> f64 {
        self.tfweight[val]
    }

    /// Given an IDF position `i` and a TF count `t`, builds the feature coefficient.
    pub fn get_coeff(&self, i: usize, t: usize) -> f64 {
        self.idfweight[i] * self.tfweight[t]
    }

    /// Returns the weight normalization factor.
    pub fn get_weight_norm(&self) -> f64 {
        self.weightnorm
    }

    /// Returns the first feature flip penalty parameter.
    pub fn get_flip_norm0(&self) -> f64 {
        self.probflip0_norm
    }

    /// Returns the first feature drop penalty parameter.
    pub fn get_diff_norm0(&self) -> f64 {
        self.probdiff0_norm
    }

    /// Returns the second feature flip penalty parameter.
    pub fn get_flip_norm1(&self) -> f64 {
        self.probflip1_norm
    }

    /// Returns the second feature drop penalty parameter.
    pub fn get_diff_norm1(&self) -> f64 {
        self.probdiff1_norm
    }

    /// Returns the final score scaling factor.
    pub fn get_scale(&self) -> f64 {
        self.scale
    }

    /// Returns the final score addend.
    pub fn get_addend(&self) -> f64 {
        self.addend
    }

    pub fn set_logarithmic_tf_weights(&mut self) {
        let log2 = 2.0f64.ln();
        for (i, w) in self.tfweight.iter_mut().enumerate() {
            *w = (1.0 + ((i + 1) as f64).ln() / log2).sqrt();
        }
    }

    /// Serializes this object as XML to a `Writer`.
    pub fn save_xml<W: Write>(&self, fwrite: &mut W) -> io::Result<()> {
        write!(fwrite, "<weightfactory scale=\"")?;
        write!(fwrite, "{}", self.scale)?;
        write!(fwrite, "\" addend=\"")?;
        write!(fwrite, "{}", self.addend)?;
        write!(fwrite, "\">\n")?;
        let scale_sqrt = self.scale.sqrt();
        for element in self.idfweight {
            write!(fwrite, " <idf>")?;
            write!(fwrite, "{}", element / scale_sqrt)?;
            write!(fwrite, "</idf>\n")?;
        }
        for element in self.tfweight {
            write!(fwrite, " <tf>")?;
            write!(fwrite, "{}", element)?;
            write!(fwrite, "</tf>\n")?;
        }
        write!(fwrite, " <weightnorm>{}</weightnorm>\n", self.weightnorm * self.scale)?;
        write!(fwrite, " <probflip0>{}</probflip0>\n", self.probflip0)?;
        write!(fwrite, " <probflip1>{}</probflip1>\n", self.probflip1)?;
        write!(fwrite, " <probdiff0>{}</probdiff0>\n", self.probdiff0)?;
        write!(fwrite, " <probdiff1>{}</probdiff1>\n", self.probdiff1)?;
        // Mirrors the Java source, which emits an opening tag rather than a closing
        // `</weightfactory>` tag here.
        write!(fwrite, "<weightfactory>\n")?;
        Ok(())
    }

    /// Condenses the weight table down to an array of doubles.
    pub fn to_array(&self) -> Vec<f64> {
        let numrows = self.get_size();
        let mut res = vec![0.0; numrows];
        let scale_sqrt = self.scale.sqrt();

        for i in 0..self.idfweight.len() {
            res[i] = self.idfweight[i] / scale_sqrt;
        }

        for i in 0..self.tfweight.len() {
            res[i + self.idfweight.len()] = self.tfweight[i];
        }

        res[numrows - 7] = self.weightnorm * self.scale;
        res[numrows - 6] = self.probflip0;
        res[numrows - 5] = self.probflip1;
        res[numrows - 4] = self.probdiff0;
        res[numrows - 3] = self.probdiff1;
        res[numrows - 2] = self.scale;
        res[numrows - 1] = self.addend;

        res
    }

    /// Initializes the `WeightFactory` from an array of doubles.
    pub fn set(&mut self, weight_array: &[f64]) -> Result<(), String> {
        let numrows = weight_array.len();
        if numrows != self.get_size() {
            return Err("Not enough values in double array".to_string());
        }
        self.scale = weight_array[numrows - 2];
        self.addend = weight_array[numrows - 1];
        self.weightnorm = weight_array[numrows - 7] / self.scale;
        self.probflip0 = weight_array[numrows - 6];
        self.probflip1 = weight_array[numrows - 5];
        self.probdiff0 = weight_array[numrows - 4];
        self.probdiff1 = weight_array[numrows - 3];
        let sqrt_scale = self.scale.sqrt();
        for i in 0..self.idfweight.len() {
            self.idfweight[i] = weight_array[i] * sqrt_scale;
        }
        for i in 0..self.tfweight.len() {
            self.tfweight[i] = weight_array[i + self.idfweight.len()];
        }
        self.update_norms();
        Ok(())
    }

    /// Builds (deserializes) this object from an XML stream.
    pub(crate) fn restore_xml<P: XmlPullParser>(
        &mut self,
        parser: &mut P,
    ) -> Result<(), XmlException> {
        let el = parser.start(&["weightfactory"])?;
        self.scale = parse_attribute(&el, "scale")?;
        self.addend = parse_attribute(&el, "addend")?;
        let scale_sqrt = self.scale.sqrt();
        for i in 0..self.idfweight.len() {
            parser.start(&["idf"])?;
            let val = parse_text(&parser.end()?)?;
            self.idfweight[i] = val * scale_sqrt;
        }
        for i in 0..self.tfweight.len() {
            parser.start(&["tf"])?;
            let val = parse_text(&parser.end()?)?;
            self.tfweight[i] = val;
        }
        parser.start(&["weightnorm"])?;
        self.weightnorm = parse_text(&parser.end()?)?;
        self.weightnorm /= self.scale;
        parser.start(&["probflip0"])?;
        self.probflip0 = parse_text(&parser.end()?)?;
        parser.start(&["probflip1"])?;
        self.probflip1 = parse_text(&parser.end()?)?;
        parser.start(&["probdiff0"])?;
        self.probdiff0 = parse_text(&parser.end()?)?;
        parser.start(&["probdiff1"])?;
        self.probdiff1 = parse_text(&parser.end()?)?;

        parser.end_matching(&el)?;
        self.update_norms();
        Ok(())
    }
}

fn parse_attribute(el: &impl XmlElement, name: &str) -> Result<f64, XmlException> {
    let value = el
        .get_attribute(name)
        .ok_or_else(|| XmlException::with_message(format!("missing attribute {}", name)))?;
    value
        .parse()
        .map_err(|_| XmlException::with_message(format!("bad {} attribute: {}", name, value)))
}

fn parse_text(el: &impl XmlElement) -> Result<f64, XmlException> {
    let text = el.get_text();
    text.parse()
        .map_err(|_| XmlException::with_message(format!("bad numeric text: {}", text)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_factory_has_expected_sizes() {
        let wf = WeightFactory::new();
        assert_eq!(wf.get_idf_size(), 512);
        assert_eq!(wf.get_tf_size(), 64);
        assert_eq!(wf.get_size(), 512 + 64 + 7);
    }

    #[test]
    fn get_coeff_multiplies_idf_and_tf_weights() {
        let mut wf = WeightFactory::new();
        wf.idfweight[3] = 2.0;
        wf.tfweight[5] = 4.0;
        assert_eq!(wf.get_coeff(3, 5), 8.0);
        assert_eq!(wf.get_idf_weight(3), 2.0);
        assert_eq!(wf.get_tf_weight(5), 4.0);
    }

    #[test]
    fn set_logarithmic_tf_weights_matches_formula() {
        let mut wf = WeightFactory::new();
        wf.set_logarithmic_tf_weights();
        let log2 = 2.0f64.ln();
        for i in 0..wf.tfweight.len() {
            let expected = (1.0 + ((i + 1) as f64).ln() / log2).sqrt();
            assert!((wf.tfweight[i] - expected).abs() < 1e-12);
        }
    }

    #[test]
    fn to_array_then_set_round_trips() {
        let mut wf = WeightFactory::new();
        wf.set_logarithmic_tf_weights();
        for i in 0..wf.idfweight.len() {
            wf.idfweight[i] = (i as f64) * 0.5;
        }
        wf.weightnorm = 3.5;
        wf.probflip0 = 0.1;
        wf.probflip1 = 0.2;
        wf.probdiff0 = 0.3;
        wf.probdiff1 = 0.4;
        wf.scale = 2.0;
        wf.addend = 1.25;
        wf.update_norms();

        let array = wf.to_array();
        assert_eq!(array.len(), wf.get_size());

        let mut restored = WeightFactory::new();
        restored.set(&array).unwrap();

        assert!((restored.get_scale() - wf.get_scale()).abs() < 1e-9);
        assert!((restored.get_addend() - wf.get_addend()).abs() < 1e-9);
        assert!((restored.get_weight_norm() - wf.get_weight_norm()).abs() < 1e-9);
        assert!((restored.get_flip_norm0() - wf.get_flip_norm0()).abs() < 1e-9);
        assert!((restored.get_flip_norm1() - wf.get_flip_norm1()).abs() < 1e-9);
        assert!((restored.get_diff_norm0() - wf.get_diff_norm0()).abs() < 1e-9);
        assert!((restored.get_diff_norm1() - wf.get_diff_norm1()).abs() < 1e-9);
        for i in 0..wf.idfweight.len() {
            assert!((restored.get_idf_weight(i) - wf.get_idf_weight(i)).abs() < 1e-6);
        }
        for i in 0..wf.tfweight.len() {
            assert!((restored.get_tf_weight(i) - wf.get_tf_weight(i)).abs() < 1e-9);
        }
    }

    #[test]
    fn set_rejects_wrong_length() {
        let mut wf = WeightFactory::new();
        let bad = vec![0.0; wf.get_size() - 1];
        assert!(wf.set(&bad).is_err());
    }

    #[test]
    fn save_xml_writes_scale_and_addend_attributes() {
        let mut wf = WeightFactory::new();
        wf.scale = 1.0;
        wf.addend = 0.5;
        let mut buf = Vec::new();
        wf.save_xml(&mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.starts_with("<weightfactory scale=\"1\" addend=\"0.5\">\n"));
        assert!(text.contains("<weightnorm>0</weightnorm>"));
    }
}
