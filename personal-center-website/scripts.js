document.getElementById('avatar-link').addEventListener('click', function(event) {
  event.preventDefault();
  var avatar = document.getElementById('avatar');
  var originalSrc = avatar.getAttribute('data-original-src') || avatar.src;

  window.open(originalSrc, '_blank');

  if (avatar.getAttribute('data-original-src')) {
    avatar.src = avatar.getAttribute('data-original-src');
    avatar.removeAttribute('data-original-src');
  } else {
    avatar.setAttribute('data-original-src', avatar.src);
    avatar.src = originalSrc;
  }
});