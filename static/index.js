function pick(metric, val){
  document.getElementById('f_'+metric).value = val;
  document.getElementById('cvssForm').submit();
}
