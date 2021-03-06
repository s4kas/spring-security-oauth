package demo;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.test.OAuth2ContextConfiguration;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;

import sparklr.common.AbstractImplicitProviderTests;

/**
 * @author Dave Syer
 */
public class ImplicitProviderTests extends AbstractImplicitProviderTests {
	
	@BeforeClass
	public static void initClient() {
		System.setProperty("http.keepAlive", "false");
	}

	@Test
	@OAuth2ContextConfiguration(ResourceOwner.class)
	public void parallelGrants() throws Exception {
		getToken();
		Collection<Future<?>> futures = new HashSet<Future<?>>();
		ExecutorService pool = Executors.newFixedThreadPool(2);
		for (int i = 0; i < 100; i++) {
			futures.add(pool.submit(new Runnable() {
				@Override
				public void run() {
					getToken();
				}
			}));
		}
		for (Future<?> future : futures) {
			future.get();
		}
	}

	private void getToken() {
		Map<String, String> form = new LinkedHashMap<String, String>();
		form.put("client_id", "my-trusted-client");
		form.put("redirect_uri", "http://anywhere");
		form.put("response_type", "token");
		form.put("scope", "read");
		ResponseEntity<Void> response = new TestRestTemplate("user", "password")
				.getForEntity(
						http.getUrl("/oauth/authorize?client_id={client_id}&redirect_uri={redirect_uri}&response_type={response_type}&scope={scope}"),
						Void.class, form);
		assertEquals("Wrong status: " + response.getHeaders(), HttpStatus.FOUND, response.getStatusCode());
		assertTrue(response.getHeaders().getLocation().toString().contains("access_token"));
	}

	protected static class ResourceOwner extends ResourceOwnerPasswordResourceDetails {
		public ResourceOwner(Object target) {
			setClientId("my-trusted-client");
			setScope(Arrays.asList("read"));
			setId(getClientId());
			setUsername("user");
			setPassword("password");
		}
	}

}
